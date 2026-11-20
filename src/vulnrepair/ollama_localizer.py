"""LLM-based vulnerability localizer using Ollama.

Reads the repository source code, sends it to an LLM along with CVE
information, and parses the model's response to extract the exact
location of the vulnerability — no human-supplied hints required.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .contracts import CodeLocation, LocalizationResult, VulnTask

# Source file extensions per language
_LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "python": (".py",),
    "javascript": (".js", ".ts", ".jsx", ".tsx"),
    "java": (".java",),
    "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".h"),
    "go": (".go",),
    "rust": (".rs",),
    "ruby": (".rb",),
    "php": (".php",),
}

# Directories always skipped when walking the repo
_SKIP_DIR_NAMES = {
    ".git", "__pycache__", ".venv", "venv", ".env",
    "node_modules", "build", "dist", ".mypy_cache",
    ".pytest_cache", ".tox", "htmlcov",
    "_vendor", "vendor",  # skip vendored third-party code
}

_MAX_SOURCE_BYTES = 160_000   # total context fed to the LLM (~40K tokens for 70B models)
_MAX_FILE_BYTES   = 60_000    # single-file cap before truncation

_JSON_OBJECT_RE = re.compile(r'\{[^{}]*"file_path"[^{}]*\}', re.DOTALL)
_FUNC_DEF_RE    = re.compile(r'def\s+(?P<name>\w+)\s*[\(:]')

# CWE → list of (regex_pattern, human_reason) pairs.
# Patterns match single source lines; only core package files are scanned
# (examples/, tests/, docs/ are excluded to avoid decoy matches).
_CWE_SCAN_RULES: dict[str, list[tuple[str, str]]] = {
    # Class / module-level mutable security containers
    "915": [
        (r"^[A-Z_][A-Z0-9_]{2,}\s*=\s*(?:set|frozenset)\s*\(", "module-level set/frozenset security container"),
        (r"^[A-Z_][A-Z0-9_]{2,}\s*=\s*\{['\"]", "module-level constant set literal"),
        (r"SAFE_TO_IMPORT|ALLOWED|WHITELIST|BLACKLIST|DENY_LIST|ALLOW_LIST", "security allow/deny list variable"),
    ],
    # Insufficiently protected credentials (header stripping on redirect)
    "522": [
        (r"(?:Authorization|Proxy.Authorization|Cookie)", "security-sensitive header name"),
        (r"(?:remove|strip|delete).*header|header.*(?:remove|strip)", "header removal logic"),
        (r"DEFAULT_REMOVE|REMOVE_HEADERS|HEADERS_TO_STRIP", "header removal constant"),
        (r"(?:redirect|location).*header|header.*redirect", "redirect header handling"),
    ],
    # Path traversal
    "22": [
        (r"os\.path\.join\s*\(", "path join — may lack normalization"),
        (r"(?:open|Path)\s*\([^)]*(?:\+|format|%)", "open/Path with string construction"),
        (r"(?:realpath|abspath|resolve)\s*\(", "path normalization (verify it's actually called)"),
        (r"\.\./|%2[Ee]|%2[Ff]", "path traversal sequence in code"),
    ],
    # SQL injection
    "89": [
        (r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)', "f-string SQL construction"),
        (r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*%[sd]', "%-format SQL construction"),
        (r'\.execute\s*\(\s*(?:f["\']|["\'][^"\']*%)', "execute() with formatted SQL"),
    ],
    # XSS
    "79": [
        (r'f["\'].*<[a-zA-Z][^>]*>', "f-string containing HTML"),
        (r'%\s*\([^)]+\)\s*s.*<|<.*%\s*\(', "%-format in HTML context"),
        (r'(?:redirect|location|href|url).*(?:format|%|f["\'])', "URL/redirect with string formatting"),
    ],
    # HTTP request smuggling — header parsing
    "444": [
        (r"def\s+\w*(?:parse|read|feed|process).*header", "header parsing function"),
        (r"header.*(?:name|value|field).*(?:encode|decode|strip|split)", "header field processing"),
        (r"(?:ASCII|latin|iso-8859|utf-8).*header|header.*(?:ASCII|latin|encode)", "header encoding validation"),
        (r"BadHttpMessage|InvalidHeader|HeaderParseError", "HTTP header error class"),
    ],
    # Open redirect
    "601": [
        (r"urljoin|urlparse|redirect.*url|location.*header", "URL join/redirect logic"),
        (r"(?:http|https|//)[^'\"]*(?:format|%|f['\"])", "URL string construction"),
    ],
}


def _cwe_prescan(
    cwe_id: str | None,
    repo: Path,
    exts: tuple[str, ...],
) -> list[dict[str, str]]:
    """Run lightweight CWE-targeted regex scan over core package source files.

    Returns up to 10 findings, each with keys file, line, code, reason.
    Test / example / docs directories are excluded to prevent decoy hits.
    """
    if not cwe_id:
        return []
    # Normalise "CWE-915" → "915"
    key = cwe_id.upper().removeprefix("CWE-").strip()
    rules = _CWE_SCAN_RULES.get(key)
    if not rules:
        return []

    compiled = [(re.compile(pat, re.IGNORECASE), reason) for pat, reason in rules]
    _skip_dirs = _SKIP_DIR_NAMES | {"test", "tests", "example", "examples", "docs", "doc", "fixtures"}
    findings: list[dict[str, str]] = []

    def _walk(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if findings.__len__() >= 10:
                return
            if entry.name.startswith(".") or entry.name in _skip_dirs:
                continue
            if entry.is_dir():
                _walk(entry)
            elif entry.is_file() and entry.suffix in exts:
                try:
                    text = entry.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for lineno, raw_line in enumerate(text.splitlines(), 1):
                    line = raw_line.strip()
                    for compiled_re, reason in compiled:
                        if compiled_re.search(line):
                            rel = entry.relative_to(repo).as_posix()
                            findings.append({
                                "file": rel,
                                "line": str(lineno),
                                "code": raw_line.rstrip()[:120],
                                "reason": reason,
                            })
                            break  # one finding per source line
                    if len(findings) >= 10:
                        return

    _walk(repo)
    return findings


@dataclass(slots=True)
class OllamaLocalizer:
    """Locate vulnerabilities in a repository using an Ollama-hosted LLM.

    Implements LocalizerProtocol.  Requires no prior knowledge of the
    vulnerability's location — only the CVE description and the source tree.
    """

    model_id: str
    base_url: str = "http://localhost:11434"
    timeout_seconds: float = 300.0
    api_key: str = ""

    def __post_init__(self) -> None:
        if not self.model_id:
            raise ValueError("model_id must not be empty")
        self.base_url = self.base_url.rstrip("/")

    async def localize(
        self, task: VulnTask, *, failure_context: str | None = None
    ) -> LocalizationResult:
        repo = Path(task.repo_path)
        exts = _LANG_EXTENSIONS.get((task.language or "python").lower(), (".py",))

        # Extract package keywords from CVE description for priority scanning.
        priority = _extract_priority_packages(task.description or "", repo)

        # Collect source files; priority packages appear first in context.
        files = _collect_source_files(repo, exts, priority_dir_names=priority)

        # Narrow the context to only files that contain candidate function names
        # extracted from the CVE description. This eliminates irrelevant files
        # that share the same package and confuse the LLM.
        func_names = _extract_function_names(task.description or "")
        if func_names:
            filtered = _filter_files_by_symbol(files, func_names)
            if filtered:
                files = filtered

        # Build the numbered source context, respecting size limits
        source_ctx = _build_source_context(files, repo)

        # CWE-guided prescan: narrow search space before prompting the LLM.
        prescan = _cwe_prescan(task.cwe_id, repo, exts)

        prompt = _build_prompt(task, source_ctx, prescan_hints=prescan, failure_context=failure_context)
        raw = await asyncio.to_thread(self._call_api, prompt)
        locations = _parse_response(raw, repo)

        return LocalizationResult(task_id=task.task_id, candidates=tuple(locations))

    def _call_api(self, prompt: str) -> str:
        import urllib.error
        import urllib.request

        payload = {
            "model": self.model_id,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security vulnerability localizer. "
                        "Analyze the given source code and CVE description to find the exact "
                        "location of the vulnerability. "
                        "Output ONLY a valid JSON object — no markdown fences, no prose."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0, "num_predict": 600},
        }
        body = json.dumps(payload).encode()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise ConnectionError(
                f"Ollama at {self.base_url} unreachable: {exc.reason}"
            ) from exc
        return str(data["message"]["content"])


# ── Symbol-based pre-filtering ────────────────────────────────────────────────


def _extract_function_names(description: str) -> list[str]:
    """Extract likely function names mentioned in the CVE description.

    Looks for camelCase or snake_case identifiers that are preceded by
    "function", "method", or similar terms.  These become grep targets so
    the LLM only sees files that actually contain the relevant symbol.
    """
    # Pattern: word "function"/"method" followed by an identifier
    names: set[str] = set()
    for m in re.finditer(
        r'(?:function|method|call|def)\s+[`\'"]*([A-Za-z_][A-Za-z0-9_]*)[`\'"]*',
        description,
        re.IGNORECASE,
    ):
        names.add(m.group(1))
    # Also pick up camelCase tokens (mixed case) that look like function names.
    # snake_case tokens are excluded unless explicitly preceded by "function"/"method"
    # above, to avoid false positives from generic words like "constructs".
    for token in re.findall(r'\b[a-z][a-zA-Z0-9]{3,}\b', description):
        if any(c.isupper() for c in token[1:]):   # camelCase only
            names.add(token)
    # Remove obvious non-function English words
    _ignore = {"function", "method", "script", "attack", "attacker", "version",
               "include", "inject", "escape", "bytes", "string", "comment",
               "anchor", "ticket", "content", "response", "redirect",
               "attacker", "supplied", "contains", "referencing"}
    return [n for n in names if n.lower() not in _ignore]


def _filter_files_by_symbol(files: list[Path], symbols: list[str]) -> list[Path]:
    """Return only files that contain a definition of at least one symbol.

    Uses a fast regex scan rather than full parsing.  Falls back to the
    original file list if no matches are found.
    """
    pattern = re.compile(
        r'def\s+(?:' + '|'.join(re.escape(s) for s in symbols) + r')\b'
    )
    matched: list[Path] = []
    for fp in files:
        try:
            if pattern.search(fp.read_text(encoding="utf-8", errors="replace")):
                matched.append(fp)
        except OSError:
            continue
    return matched


# ── File collection ───────────────────────────────────────────────────────────


def _extract_priority_packages(description: str, repo: Path) -> list[str]:
    """Return sub-package directory names that appear in the CVE description AND exist in the repo.

    Enables package-aware scanning: for large repos the alphabetical walk may
    exhaust the context budget before reaching the vulnerable package.  By
    scanning matching sub-package directories first we ensure the relevant code
    is visible to the LLM even when the repo is large.

    Only directories at exactly depth src/PKG/SUBPKG (one level below the
    top-level package) are considered to avoid accidentally matching the
    top-level package directory, which would trigger a full alphabetical walk.
    """
    _STOPWORDS = {
        "the", "and", "for", "with", "in", "of", "to", "is", "an",
        "or", "by", "on", "are", "url", "html", "can", "xss", "via",
        "its", "that", "this", "from", "not", "into", "any", "even",
        "just", "only", "when", "which", "who", "does", "has", "was",
        # programming language names — never sub-package names
        "python", "javascript", "typescript", "java", "ruby", "rust",
        "golang", "php", "swift", "kotlin", "scala", "haskell",
    }
    words = set(re.findall(r'\b[a-z][a-z0-9_]{2,}\b', description.lower())) - _STOPWORDS
    matched: set[str] = set()

    src_dir = repo / "src"
    if src_dir.is_dir():
        try:
            # Look only one level below each top-level package directory:
            # src/PKG/SUBPKG  — avoiding the top-level package name itself.
            for pkg_dir in src_dir.iterdir():
                if not pkg_dir.is_dir() or pkg_dir.name in _SKIP_DIR_NAMES:
                    continue
                for subpkg in pkg_dir.iterdir():
                    if subpkg.is_dir() and subpkg.name in words and subpkg.name not in _SKIP_DIR_NAMES:
                        matched.add(subpkg.name)
        except OSError:
            pass
    else:
        # For repos without a src/ layout (e.g. flat PKG/SUBPKG at repo root),
        # look one level below each top-level package directory.
        try:
            for pkg_dir in sorted(repo.iterdir()):
                if not pkg_dir.is_dir() or pkg_dir.name in _SKIP_DIR_NAMES or pkg_dir.name.startswith("."):
                    continue
                for subpkg in sorted(pkg_dir.iterdir()):
                    if subpkg.is_dir() and subpkg.name in words and subpkg.name not in _SKIP_DIR_NAMES:
                        matched.add(subpkg.name)
        except OSError:
            pass

    return list(matched)


def _collect_source_files(
    repo: Path,
    extensions: tuple[str, ...],
    priority_dir_names: list[str] | None = None,
) -> list[Path]:
    """Return source files, prioritising priority packages then src/ directory.

    For large repos the alphabetical depth-first walk may fill the context
    budget before reaching the vulnerable package.  *priority_dir_names* lists
    directory names (e.g. ``["web"]``) that are scanned first so their files
    appear at the top of the context window.
    """
    seen: set[Path] = set()
    collected: list[Path] = []

    def _walk(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in _SKIP_DIR_NAMES or entry.name.startswith("."):
                    continue
                _walk(entry)
            elif entry.is_file() and entry.suffix in extensions:
                if entry not in seen:
                    seen.add(entry)
                    collected.append(entry)

    src_dir = repo / "src"

    # Phase 1: Walk any directories whose names match priority keywords first.
    # This ensures the LLM sees the relevant package even in a large repo.
    # Works for both src/ layouts and flat PKG/SUBPKG layouts at repo root.
    if priority_dir_names:
        priority_set = set(priority_dir_names)
        search_root = src_dir if src_dir.is_dir() else repo
        try:
            for entry in sorted(search_root.rglob("*")):
                if (entry.is_dir()
                        and entry.name in priority_set
                        and entry.name not in _SKIP_DIR_NAMES
                        and not entry.name.startswith(".")):
                    _walk(entry)
        except OSError:
            pass

    # Phase 2: Normal alphabetical walk (already-seen files are deduplicated).
    if src_dir.is_dir():
        _walk(src_dir)

    # Walk remaining top-level entries (exclude src/ already done).
    # Also collect plain files at the repo root (e.g. a single-file vulnerable module).
    try:
        for entry in sorted(repo.iterdir()):
            if entry.name == "src":
                continue
            if entry.name in _SKIP_DIR_NAMES or entry.name.startswith("."):
                continue
            if entry.is_file() and entry.suffix in extensions and entry not in seen:
                seen.add(entry)
                collected.append(entry)
            elif entry.is_dir():
                _walk(entry)
    except OSError:
        pass

    return collected


def _build_source_context(files: list[Path], repo: Path) -> str:
    parts: list[str] = []
    total_bytes = 0

    for fp in files:
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Truncate oversized individual files
        encoded = raw.encode("utf-8", errors="replace")
        if len(encoded) > _MAX_FILE_BYTES:
            raw = encoded[:_MAX_FILE_BYTES].decode("utf-8", errors="replace")
            raw += "\n... (file truncated)"

        numbered = "\n".join(
            f"{i + 1:5d}: {line}"
            for i, line in enumerate(raw.splitlines())
        )
        rel = fp.relative_to(repo).as_posix()
        entry = f"=== {rel} ===\n{numbered}\n"
        entry_bytes = len(entry.encode("utf-8"))

        if total_bytes + entry_bytes > _MAX_SOURCE_BYTES:
            break   # context window full

        parts.append(entry)
        total_bytes += entry_bytes

    return "\n".join(parts)


# ── Prompt construction ───────────────────────────────────────────────────────


def _build_prompt(
    task: VulnTask,
    source_context: str,
    prescan_hints: list[dict[str, str]] | None = None,
    failure_context: str | None = None,
) -> str:
    cve_line = f"  CVE ID  : {task.cve_id}\n" if task.cve_id else ""

    # Failure-feedback block: placed at the very top so the LLM reads it first.
    # Truncated to 400 chars to avoid dominating the context.
    if failure_context:
        snippet = failure_context.strip()[:400]
        failure_block = (
            "PREVIOUS LOCALIZATION ATTEMPT FAILED — REVISE YOUR ANSWER:\n"
            f"  PoC evidence from previous run: {snippet}\n"
            "  Your earlier location did NOT fix the vulnerability.\n"
            "  Use the failure evidence above to identify a DIFFERENT, more specific location.\n"
            "\n"
        )
    else:
        failure_block = ""

    # Render prescan findings as a focused hint block (max 10 entries).
    if prescan_hints:
        hint_lines = [
            f"  {h['file']}:{h['line']}  [{h['reason']}]  {h['code']}"
            for h in prescan_hints[:10]
        ]
        prescan_block = (
            "\nPre-scan findings (CWE-" + (task.cwe_id or "?").upper().removeprefix("CWE-") +
            " patterns matched — investigate these lines first):\n" +
            "\n".join(hint_lines) + "\n"
        )
    else:
        prescan_block = ""

    return (
        f"{failure_block}"
        "You are a vulnerability analyst. Find the exact source location of the security bug below.\n"
        "\n"
        "Vulnerability:\n"
        f"{cve_line}"
        f"  CWE     : {task.cwe_id}\n"
        f"  Summary : {task.description}\n"
        f"{prescan_block}"
        "\n"
        "Strategy — work through these steps before answering:\n"
        "1. Identify what feature or operation the vulnerability affects "
        "(e.g. 'HTML attribute key validation in xmlattr filter').\n"
        "2. Search the source code for the function or method that implements that feature.\n"
        "3. Inside that function, find the specific lines that perform validation, "
        "sanitization, or security checks — these are the most likely location of the flaw.\n"
        "4. Pick the tightest region that includes the flawed check AND any closely related "
        "constants or compiled patterns defined just before the function.\n"
        "\n"
        "Repository source code (line numbers on the left):\n"
        f"{source_context}\n"
        "\n"
        "Output ONLY a JSON object — no markdown, no prose, no extra keys:\n"
        "{{\n"
        '  "file_path"     : "path/relative/to/repo/root.ext",\n'
        '  "function_name" : "exact_function_name_from_the_source",\n'
        '  "start_line"    : <integer: first line of the vulnerable region>,\n'
        '  "end_line"      : <integer: last line of the vulnerable region>,\n'
        '  "confidence"    : <float 0.0-1.0>,\n'
        '  "rationale"     : "one sentence: which line is wrong and why"\n'
        "}}"
    )


# ── Response parsing ──────────────────────────────────────────────────────────


def _parse_response(raw: str, repo: Path) -> list[CodeLocation]:
    """Extract a CodeLocation from the LLM's JSON response."""
    text = raw.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        first_nl = text.find("\n")
        last_fence = text.rfind("```")
        if first_nl > 0 and last_fence > first_nl:
            text = text[first_nl + 1 : last_fence].strip()

    data: object = None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Fall back: search for a JSON object containing "file_path"
        m = _JSON_OBJECT_RE.search(text)
        if m:
            try:
                data = json.loads(m.group())
            except json.JSONDecodeError:
                pass

    if not isinstance(data, dict):
        return []

    try:
        file_path    = str(data.get("file_path", "")).strip()
        func_name    = str(data.get("function_name", "")).strip() or None
        start_line   = int(data["start_line"])
        end_line     = int(data["end_line"])
        confidence   = float(data.get("confidence", 0.8))
        rationale    = str(data.get("rationale", "")).strip()
    except (KeyError, TypeError, ValueError):
        return []

    if not file_path:
        return []

    repo_file = repo / file_path
    if not repo_file.is_file():
        return []

    # LLMs often know the function name but hallucinate line numbers.
    # Correct the range by searching the actual file for the function definition.
    if func_name:
        corrected = _find_function_range(repo_file, func_name)
        if corrected is not None:
            start_line, end_line = corrected

    if start_line < 1 or end_line < start_line:
        return []

    confidence = max(0.0, min(1.0, confidence))
    rationale  = rationale or f"LLM identified {file_path}:{start_line}-{end_line}"

    try:
        location = CodeLocation(
            file_path=file_path,
            function_name=func_name,
            start_line=start_line,
            end_line=end_line,
            confidence=confidence,
            rationale=rationale,
        )
    except Exception:
        return []

    return [location]


def _find_function_range(repo_file: Path, function_name: str) -> tuple[int, int] | None:
    """Locate a function in a Python source file and return its 1-indexed line range.

    Handles:
    - ``def do_<name>`` and ``def <name>`` variants
    - Multi-line function signatures (e.g. `) -> str:` on its own line)
    - Decorators immediately before the def
    - Related module-level variables just above the decorator block
      (e.g. ``_space_re`` compiled just before ``do_xmlattr``)
    """
    try:
        lines = repo_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    bare = re.sub(r"^do_", "", function_name.lstrip("_"))
    candidates = {function_name, f"do_{bare}", bare}

    # Step 1 — Find the "def" line.
    func_line_0: int | None = None
    for i, line in enumerate(lines):
        m = _FUNC_DEF_RE.search(line)
        if m and m.group("name") in candidates:
            func_line_0 = i
            break

    if func_line_0 is None:
        return None

    func_indent = len(lines[func_line_0]) - len(lines[func_line_0].lstrip())

    # Step 2 — Walk past the function signature to find the body-opening colon.
    # Multi-line sigs look like:  def foo(\n    arg\n) -> str:
    body_start_0 = func_line_0
    for i in range(func_line_0, min(func_line_0 + 15, len(lines))):
        rstripped = lines[i].rstrip()
        # The colon ending the signature is at the def's indent level or on a
        # closing-paren line.
        if rstripped.endswith(":") and (
            i == func_line_0 or lines[i].lstrip().startswith(")")
        ):
            body_start_0 = i
            break

    # Step 3 — Backward search: include decorators, then related module-level vars.
    start_0 = func_line_0
    for i in range(func_line_0 - 1, max(-1, func_line_0 - 20), -1):
        stripped = lines[i].strip()
        if not stripped:
            break  # blank line — stop here, check for vars below
        if stripped.startswith("@"):
            start_0 = i   # decorator: part of the function block
        elif len(lines[i]) - len(lines[i].lstrip()) == 0:
            break  # another top-level item, stop
        else:
            break

    # Step 3b — Look back past blank lines for an immediately preceding
    # module-level variable (e.g. _space_re = re.compile(...)).
    for i in range(start_0 - 1, max(-1, start_0 - 6), -1):
        stripped = lines[i].strip()
        if not stripped:
            continue   # skip blank lines
        line_indent = len(lines[i]) - len(lines[i].lstrip())
        if line_indent == 0 and "=" in stripped and not stripped.startswith(("def ", "class ")):
            start_0 = i
        break   # always stop after the first non-blank line (match or not)

    # Step 4 — Forward search: find end of function body.
    # Tracks triple-quoted string nesting so that low-indentation content
    # inside multiline string literals (e.g. HTML templates in bytes literals)
    # does NOT trigger a premature function-body break.
    end_0 = body_start_0
    in_triple_quote = False
    triple_delim = ""
    for i in range(body_start_0 + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()

        # Toggle triple-quote state and detect whether this line is a
        # string-internal or string-closing line.
        was_in_triple = in_triple_quote
        for delim in ('"""', "'''"):
            count = line.count(delim)
            if count:
                if not in_triple_quote:
                    in_triple_quote = True
                    triple_delim = delim
                    if count % 2 == 0:        # opened and closed on same line
                        in_triple_quote = False
                elif delim == triple_delim:
                    if count % 2 != 0:        # closing delimiter
                        in_triple_quote = False
                break
        # A line that was inside (or just closed) a string is still body.
        string_line = was_in_triple or (was_in_triple != in_triple_quote)

        if not stripped or stripped.startswith("#"):
            end_0 = i
            continue
        # Inside a multiline string any indentation is data, not structure.
        if string_line or in_triple_quote:
            end_0 = i
            continue
        if len(line) - len(line.lstrip()) <= func_indent:
            break   # genuine scope exit (next top-level definition)
        end_0 = i

    return start_0 + 1, end_0 + 1   # convert to 1-indexed


__all__ = ["OllamaLocalizer"]
