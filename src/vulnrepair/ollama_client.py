"""Ollama model client implementing ModelClientProtocol.

Sends requests to an Ollama inference server (local or remote) using the
native /api/chat endpoint — no extra Python dependencies required.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .models import ModelResponse


@dataclass(slots=True)
class OllamaModelClient:
    """HTTP adapter for any Ollama-hosted model.

    Works with local models (llama3.3:70b) and cloud-relay models
    (kimi-k2.7-code:cloud, deepseek-v4-pro:cloud, …) alike.

    Use ``api_key`` when the server is configured with OLLAMA_API_KEY,
    or leave it as the empty string when connecting via an SSH tunnel
    (tunnel enforces auth at the transport layer instead).
    """

    model_id: str
    base_url: str = "http://localhost:11434"
    timeout_seconds: float = 600.0
    api_key: str = ""

    def __post_init__(self) -> None:
        if not self.model_id:
            raise ValueError("model_id must not be empty")
        self.base_url = self.base_url.rstrip("/")

    async def complete(
        self,
        prompt: str,
        *,
        temperature: float,
        max_tokens: int,
        max_cost_usd: float,
    ) -> ModelResponse:
        del max_cost_usd  # Ollama carries no per-call billing
        return await asyncio.to_thread(self._call_api, prompt, temperature, max_tokens)

    def _call_api(self, prompt: str, temperature: float, max_tokens: int) -> ModelResponse:
        payload = {
            "model": self.model_id,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security patch generator.\n"
                        "Follow the output format requested in the user message EXACTLY.\n"
                        "The user message will ask you to output either a SEARCH/REPLACE block "
                        "or a unified Git diff — output ONLY that format, nothing else.\n"
                        "No explanations, no markdown, no commentary.\n"
                        "Critical rules (apply to both formats):\n"
                        "1. SEARCH/REPLACE: the SEARCH block must be copied VERBATIM from the "
                        "source — every character, every space, every blank line exactly as shown.\n"
                        "2. Unified diff: context lines (space-prefixed) MUST be copied VERBATIM "
                        "from the source. Count blank lines exactly as they appear in the source.\n"
                        "3. Do NOT add new import statements unless absolutely required.\n"
                        "4. Keep changes minimal — modify only the lines needed to fix the "
                        "vulnerability. Do not refactor or add unrelated changes.\n"
                        "5. If you rename a symbol, update ALL references to it."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
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
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read()
        except urllib.error.URLError as exc:
            raise ConnectionError(
                f"Ollama at {self.base_url} unreachable: {exc.reason}"
            ) from exc
        latency = time.monotonic() - t0

        data = json.loads(raw)
        raw_text: str = data["message"]["content"]

        # Parse the numbered source listing from the prompt so we can validate
        # and correct context lines in the model's diff.
        source_lines = _parse_source_context(prompt)
        text = _extract_diff(raw_text, source_lines)

        return ModelResponse(
            text=text,
            model_id=self.model_id,
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
            cost_usd=0.0,
            latency_seconds=latency,
        )


# ── Source-context parser ─────────────────────────────────────────────────────

_SOURCE_LINE_RE = re.compile(r"^\s{0,5}(\d+): ?(.*)$")


def _parse_source_context(prompt: str) -> dict[int, str]:
    """Extract the numbered source listing from a build_patch_prompt string.

    The prompt contains a section like::

        Source context:
           248:     yield from value.items()
           249:
           250:
           251: _space_re = re.compile(r"\\s", flags=re.ASCII)
           ...
        Previously rejected attempts:
        ...

    Returns a dict mapping line_number → line_content (no trailing newline).
    """
    source: dict[int, str] = {}
    capturing = False
    for text_line in prompt.splitlines():
        # Accept both "Source context" (old format) and "Source code" (new format)
        if text_line.startswith("Source context") or text_line.startswith("Source code"):
            capturing = True
            continue
        if not capturing:
            continue
        if text_line.startswith("Previously rejected") or text_line.startswith("Now output"):
            break
        m = _SOURCE_LINE_RE.match(text_line)
        if m:
            source[int(m.group(1))] = m.group(2)
    return source


# ── Diff extraction and normalisation ────────────────────────────────────────


def _extract_diff(text: str, source_lines: dict[int, str] | None = None) -> str:
    """Best-effort extraction of a unified diff from a model response.

    Models sometimes add explanatory prose before or after the diff even when
    instructed not to.  This strips everything outside the diff block so that
    extract_unified_diff() in models.py can parse it cleanly.
    """
    stripped = text.strip()

    # Handle markdown code fence: ```diff\n...\n``` or ```\n...\n```
    if stripped.startswith("```"):
        first_nl = stripped.find("\n")
        last_fence = stripped.rfind("```")
        if first_nl > 0 and last_fence > first_nl:
            inner = stripped[first_nl + 1 : last_fence].strip()
            if "diff --git " in inner or inner.startswith("diff --git "):
                return _fix_hunk_headers(inner, source_lines)

    # Find the diff marker anywhere in the text
    idx = stripped.find("diff --git ")
    if idx >= 0:
        return _fix_hunk_headers(stripped[idx:], source_lines)

    return stripped


# Matches the @@ -old_start[,old_count] +new_start[,new_count] @@ header
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")

# Matches the 'diff --git a/path b/path' line; captures the b-side path
_GIT_DIFF_RE = re.compile(r"^diff --git a/.+ b/(.+)$")

# Valid git diff metadata lines that may appear before the first @@ hunk
_DIFF_META_PREFIXES = (
    "index ", "old mode", "new mode", "new file mode", "deleted file mode",
    "similarity index", "rename from", "rename to", "copy from", "copy to",
    "--- ", "+++ ",
)


def _find_hunk_start(
    body: list[str], approximate_start: int, source_lines: dict[int, str]
) -> int:
    """Search for the actual old-file start line by matching the first non-blank body line.

    The model often uses the changed line's number as the hunk start instead of the
    first context line's number.  Search source_lines within a ±30-line window for
    the content of the first non-blank, non-added body line so we can correct it.
    """
    for bl in body:
        if bl.startswith("\\") or bl.startswith("+"):
            continue
        candidate = bl[1:].rstrip("\n\r")  # strip space-or-minus prefix
        if not candidate:  # skip blank anchor lines — not useful for search
            continue
        for delta in range(0, 31):
            for sign in ([0] if delta == 0 else [-1, 1]):
                lineno = approximate_start + sign * delta
                if lineno in source_lines and source_lines[lineno] == candidate:
                    return lineno
        break  # first non-blank line not found nearby — give up
    return approximate_start


_NO_CHANGE_RE = re.compile(r"#\s*no.?change", re.IGNORECASE)


def _is_garbage_hunk(counted: list[str]) -> bool:
    """Return True if a hunk contains a placeholder 'no change' comment in any added line.

    Models sometimes append hunks that signal the rest of the file is unchanged,
    e.g. '+    # no change needed below this line'.  These are not real patches.
    """
    return any(
        bl.startswith("+") and bool(_NO_CHANGE_RE.search(bl)) for bl in counted
    )


def _is_noop_hunk(counted: list[str]) -> bool:
    """Return True if every removed line has an identical added counterpart.

    Such hunks change nothing and confuse 'git apply'; they should be dropped.
    """
    minus = [bl[1:].rstrip("\n\r") for bl in counted if bl.startswith("-")]
    plus  = [bl[1:].rstrip("\n\r") for bl in counted if bl.startswith("+")]
    return bool(minus) and minus == plus


def _dedup_plus_lines(body: list[str]) -> list[str]:
    """Drop a '+' line whose stripped content equals the immediately following context line.

    Models sometimes emit an added line followed by a context line with identical
    content — i.e. they add a line that already exists in the source.  Keeping both
    would insert a duplicate into the target file; dropping the '+' leaves the
    already-present source line untouched.
    """
    result: list[str] = []
    n = len(body)
    i = 0
    while i < n:
        bl = body[i]
        if (
            bl.startswith("+")
            and i + 1 < n
            and body[i + 1].startswith(" ")
            and bl[1:].strip() == body[i + 1][1:].strip()
        ):
            i += 1  # drop this duplicate + line
            continue
        result.append(bl)
        i += 1
    return result


def _strip_added_trailing_ws(body: list[str]) -> list[str]:
    """Strip trailing whitespace from added lines.

    git apply --whitespace=error-all rejects patches that add lines with trailing
    spaces or tabs (e.g. blank lines inside docstrings emitted as '+        \\n').
    Stripping those characters is semantically safe for Python source code.
    """
    result: list[str] = []
    for bl in body:
        if bl.startswith("+"):
            stripped = bl.rstrip("\r\n").rstrip()
            terminator = bl[len(bl.rstrip("\r\n")):]
            result.append(stripped + terminator)
        else:
            result.append(bl)
    return result


def _fix_hunk_headers(diff: str, source_lines: dict[int, str] | None = None) -> str:
    """Recompute @@ hunk headers and correct context lines from the actual source.

    Five common LLM failure modes are fixed:
    1. Wrong old/new start line (model uses changed-line number, not first-context-line number).
    2. Wrong line counts in the @@ header (recalculated from the body).
    3. Hallucinated blank context lines that don't exist in the source
       (detected and dropped when source_lines is supplied).
    4. Stray blank/context lines between 'diff --git' and the first '@@ ' hunk
       (dropped — they are not valid in the git diff preamble).
    5. Missing '--- a/path' / '+++ b/path' path headers before the first hunk
       (inserted automatically from the 'diff --git a/path b/path' line).
    """
    lines = diff.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    running_delta = 0  # net line additions accumulated from previous hunks

    # Per-file preamble tracking
    current_b_path: str | None = None   # b-side path from 'diff --git'
    has_old_header = False               # whether '--- a/...' was seen for this file
    has_new_header = False               # whether '+++ b/...' was seen for this file
    in_preamble = False                  # True between 'diff --git' and first '@@'
    seen_paths: set[str] = set()        # paths already processed (detect duplicates)
    skip_to_next_file = False           # True when skipping a duplicate file section

    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip("\n\r")

        # New file section
        git_m = _GIT_DIFF_RE.match(stripped)
        if git_m:
            new_b_path = git_m.group(1)
            if new_b_path in seen_paths:
                # Duplicate diff --git block for the same path — LLM sometimes
                # repeats the patch or appends garbage.  Skip until the next file.
                skip_to_next_file = True
                i += 1
                continue
            skip_to_next_file = False
            seen_paths.add(new_b_path)
            current_b_path = new_b_path
            has_old_header = False
            has_new_header = False
            in_preamble = True
            running_delta = 0
            out.append(line)
            i += 1
            continue

        # Skip every line belonging to a duplicate file section.
        if skip_to_next_file:
            i += 1
            continue

        # Path headers (--- / +++)
        # A second '--- a/...' after we have already seen both '---' and '+++'
        # (i.e. has_old_header and has_new_header) means the model repeated the
        # patch or appended a garbage block.  Treat it like a duplicate 'diff --git'
        # and skip everything until the next real file section.
        if stripped.startswith("--- "):
            if has_old_header and has_new_header:
                skip_to_next_file = True
                i += 1
                continue
            has_old_header = True
            in_preamble = False
            out.append(line)
            i += 1
            continue

        if stripped.startswith("+++ "):
            if has_new_header:  # spurious second +++
                skip_to_next_file = True
                i += 1
                continue
            has_new_header = True
            in_preamble = False
            out.append(line)
            i += 1
            continue

        # Other valid metadata lines in the preamble
        if in_preamble and any(stripped.startswith(p) for p in _DIFF_META_PREFIXES):
            out.append(line)
            i += 1
            continue

        m = _HUNK_RE.match(stripped)
        if not m:
            if in_preamble:
                # Drop stray lines (blank, space-only, prose) before the first @@
                i += 1
                continue
            out.append(line)
            i += 1
            continue

        # It's a @@ hunk header
        in_preamble = False

        # Insert missing --- / +++ path headers before the first hunk
        if current_b_path and not (has_old_header and has_new_header):
            out.append(f"--- a/{current_b_path}\n")
            out.append(f"+++ b/{current_b_path}\n")
            has_old_header = True
            has_new_header = True

        old_start = int(m.group(1))
        suffix = m.group(3)  # anything after the second @@, e.g. function name

        # Collect raw hunk body, normalising bare blank lines to " \n"
        raw_body: list[str] = []
        j = i + 1
        while j < len(lines):
            bl = lines[j]
            if (
                bl.startswith("@@")
                or bl.startswith("diff ")
                or bl.startswith("--- ")
                or bl.startswith("+++ ")
            ):
                break
            if bl in ("\n", "\r\n", ""):
                bl = " \n"
            raw_body.append(bl)
            j += 1

        # Fix the old_start when the model used the changed-line number instead
        # of the first context line's number, then correct context lines.
        if source_lines:
            old_start = _find_hunk_start(raw_body, old_start, source_lines)
            new_start = old_start + running_delta
            body = _apply_source_context(raw_body, old_start, source_lines)
        else:
            new_start = old_start + running_delta
            body = raw_body

        # Drop + lines whose content duplicates the immediately following context line
        # (model added a line that already exists in source — would create a duplicate).
        body = _dedup_plus_lines(body)

        # Strip trailing whitespace from added lines so git apply --whitespace=error-all
        # doesn't reject the patch (LLM often emits blank docstring lines as "+        \n").
        body = _strip_added_trailing_ws(body)

        # "\ No newline at end of file" lines are not counted in git's totals
        counted = [bl for bl in body if not bl.startswith("\\")]
        has_changes = any(bl.startswith(("+", "-")) for bl in counted)

        # Skip pure-context hunks (no +/- lines) — they are no-ops and often
        # have wrong start-line numbers that cause git apply to fail.
        if not has_changes:
            i = j
            continue

        # Skip no-op hunks where every removed line is identical to the
        # corresponding added line (LLM sometimes emits "- foo\n+ foo\n").
        if _is_noop_hunk(counted):
            i = j
            continue

        # Skip garbage hunks containing placeholder "no change" comments.
        if _is_garbage_hunk(counted):
            i = j
            continue

        old_count = sum(1 for bl in counted if not bl.startswith("+"))
        new_count = sum(1 for bl in counted if not bl.startswith("-"))
        running_delta += new_count - old_count

        old_part = f"{old_start}" if old_count == 1 else f"{old_start},{old_count}"
        new_part = f"{new_start}" if new_count == 1 else f"{new_start},{new_count}"
        out.append(f"@@ -{old_part} +{new_part} @@{suffix}\n")
        out.extend(body)
        i = j

    return "".join(out)


def _apply_source_context(
    body: list[str],
    old_start: int,
    source_lines: dict[int, str],
) -> list[str]:
    """Rewrite context lines in a hunk body using the actual source content.

    The key correction: a blank context line (" \\n") that the model placed where
    the actual source has non-blank content is a hallucination — it is dropped.
    Non-blank context lines are replaced with the verified source text to fix
    any minor wording or whitespace differences introduced by the model.

    Additionally, when a + line immediately follows a - line and the + line has
    *less* indentation than the source line being removed, the source indentation
    is copied to the + line — correcting a common LLM mistake where the model
    strips leading whitespace from replacement lines.
    """
    result: list[str] = []
    old_lineno = old_start
    last_removed_indent: str | None = None  # indent of the most recent - line

    for bl in body:
        if bl.startswith("\\"):
            result.append(bl)
            continue

        if bl.startswith("+"):
            content = bl[1:].rstrip("\n\r")
            if last_removed_indent is not None:
                stripped = content.lstrip()
                current_indent = content[: len(content) - len(stripped)]
                # If model used less indentation than the removed source line, restore it.
                if len(current_indent) < len(last_removed_indent):
                    content = last_removed_indent + stripped
            result.append(f"+{content}\n")
            # Keep last_removed_indent for consecutive + lines (model may underdent
            # all added lines in a block, not just the first one).
            continue

        if bl.startswith("-"):
            content = bl[1:].rstrip("\n\r")
            if old_lineno in source_lines:
                actual = source_lines[old_lineno]
                if actual == content:
                    # Perfect match — normal case.
                    result.append(f"-{actual}\n")
                    last_removed_indent = actual[: len(actual) - len(actual.lstrip())]
                    old_lineno += 1
                else:
                    # Mismatch: the model skipped context lines.  Search forward in a
                    # small window for the line the model intended to remove.
                    found_lineno: int | None = None
                    for search_lineno in range(old_lineno + 1, old_lineno + 20):
                        if search_lineno in source_lines and source_lines[search_lineno] == content:
                            found_lineno = search_lineno
                            break
                    if found_lineno is not None:
                        # Fill in the skipped source lines as context lines.
                        while old_lineno < found_lineno:
                            if old_lineno in source_lines:
                                result.append(f" {source_lines[old_lineno]}\n")
                            old_lineno += 1
                        result.append(f"-{source_lines[found_lineno]}\n")
                        last_removed_indent = content[: len(content) - len(content.lstrip())]
                        old_lineno = found_lineno + 1
                    else:
                        # No match found nearby — keep model content as-is.
                        result.append(bl if bl.endswith("\n") else bl + "\n")
                        last_removed_indent = content[: len(content) - len(content.lstrip())]
                        old_lineno += 1
            else:
                result.append(bl if bl.endswith("\n") else bl + "\n")
                last_removed_indent = content[: len(content) - len(content.lstrip())]
                old_lineno += 1
            continue

        # Context line (space-prefixed or normalised blank) — resets indent tracking
        last_removed_indent = None
        is_blank_context = bl.rstrip("\n\r") in ("", " ")
        if old_lineno in source_lines:
            actual = source_lines[old_lineno]
            if is_blank_context and actual != "":
                # Model hallucinated a blank line that is non-blank in source — drop it
                continue
            result.append(f" {actual}\n")
            old_lineno += 1
        else:
            # Line falls outside the context window — keep model's content as-is
            result.append(bl if bl.endswith("\n") else bl + "\n")
            old_lineno += 1

    return result


@dataclass(slots=True)
class OllamaReplacementClient:
    """Ollama client that asks the model to rewrite the vulnerable function body.

    Small models often hallucinate context lines when asked to write full unified diffs,
    especially for files that mix Python code with embedded HTML/bytes literals.
    This client sidesteps that by asking the model for the corrected function text as JSON,
    then computing a syntactically valid unified diff with difflib from the old vs new function.
    """

    model_id: str
    base_url: str = "http://localhost:11434"
    timeout_seconds: float = 600.0
    api_key: str = ""

    def __post_init__(self) -> None:
        if not self.model_id:
            raise ValueError("model_id must not be empty")
        self.base_url = self.base_url.rstrip("/")

    async def complete(
        self,
        prompt: str,
        *,
        temperature: float,
        max_tokens: int,
        max_cost_usd: float,
    ) -> ModelResponse:
        del max_cost_usd
        return await asyncio.to_thread(self._call_api, prompt, temperature, max_tokens)

    def _call_api(self, prompt: str, temperature: float, max_tokens: int) -> ModelResponse:
        source_lines = _parse_source_context(prompt)
        file_path = _extract_file_path_from_prompt(prompt)
        func_range = _extract_func_range_from_prompt(prompt)
        narrow_ctx = _build_narrow_context(source_lines, func_range)

        inner_prompt = _build_rewrite_inner_prompt(prompt, narrow_ctx)

        payload = {
            "model": self.model_id,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security engineer fixing a real security vulnerability.\n"
                        "Output ONLY valid JSON listing the changed lines:\n"
                        '{"changes": ['
                        '{"old_stripped": "original line content without indentation", '
                        '"new_stripped": "replacement content without indentation"},'
                        '{"old_stripped": "line to delete", "new_stripped": null},'
                        "...one entry per changed or deleted line"
                        "]}\n"
                        "Rules:\n"
                        "- old_stripped: the line content WITHOUT leading/trailing whitespace\n"
                        "- new_stripped: replacement WITHOUT leading/trailing whitespace, "
                        "or null to DELETE the line entirely\n"
                        "- Quote characters inside JSON strings: use \\\" for literal double-quotes\n"
                        "- Output ONLY the JSON object, no prose, no markdown fences"
                    ),
                },
                {"role": "user", "content": inner_prompt},
            ],
            "stream": False,
            "think": False,  # disable Qwen3 thinking mode at top level (ignored by other models)
            "format": "json",
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
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
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw = resp.read()
        except urllib.error.URLError as exc:
            raise ConnectionError(
                f"Ollama at {self.base_url} unreachable: {exc.reason}"
            ) from exc
        latency = time.monotonic() - t0

        data = json.loads(raw)
        raw_text: str = data["message"]["content"]

        diff = _construct_diff_from_changes_json(
            raw_text, file_path, source_lines, func_range
        )

        return ModelResponse(
            text=diff,
            model_id=self.model_id,
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
            cost_usd=0.0,
            latency_seconds=latency,
        )


# ── Replacement client helpers ────────────────────────────────────────────────

_FILE_PATH_RE = re.compile(r"^Vulnerable file:\s*(.+)$", re.MULTILINE)
_FUNC_RANGE_RE = re.compile(r"^Vulnerable lines:\s*(\d+)[–\-](\d+)", re.MULTILINE)


def _extract_file_path_from_prompt(prompt: str) -> str:
    m = _FILE_PATH_RE.search(prompt)
    return m.group(1).strip() if m else "unknown/file.py"


def _extract_func_range_from_prompt(prompt: str) -> tuple[int, int]:
    m = _FUNC_RANGE_RE.search(prompt)
    if m:
        return int(m.group(1)), int(m.group(2))
    return 1, 9999


def _build_narrow_context(source_lines: dict[int, str], func_range: tuple[int, int]) -> str:
    """Return only the lines within the function range (plus a few lines of surrounding code)."""
    start, end = func_range
    pad = 3
    lo = max(1, start - pad)
    hi = end + pad
    parts: list[str] = []
    for n in range(lo, hi + 1):
        if n in source_lines:
            parts.append(f"{n:>6}: {source_lines[n]}")
    return "\n".join(parts)


def _extract_previous_rejections(full_prompt: str) -> str:
    """Extract the 'Previously rejected patches' block from a build_patch_prompt string."""
    capturing = False
    lines: list[str] = []
    for text_line in full_prompt.splitlines():
        if text_line.startswith("Previously rejected patches"):
            capturing = True
            lines.append(text_line)
            continue
        if capturing:
            # Stop at the trailing instruction line
            if text_line.startswith("Now output the diff"):
                break
            lines.append(text_line)
    return "\n".join(lines).strip()


def _build_rewrite_inner_prompt(full_prompt: str, narrow_ctx: str) -> str:
    cve_line = ""
    for line in full_prompt.splitlines():
        if line.startswith("CVE:") or line.startswith("CWE:") or line.startswith("Vulnerability:"):
            cve_line += line + "\n"

    rejections = _extract_previous_rejections(full_prompt)
    rejection_block = (
        f"\n\n{rejections}\n\nDo NOT repeat any of the above approaches."
        if rejections else ""
    )

    return (
        f"{cve_line.strip()}\n\n"
        "Here is the vulnerable function "
        "(line numbers on left for reference only):\n"
        f"{narrow_ctx}\n\n"
        "Fix the security vulnerability described above. "
        "Keep the function's normal, legitimate behavior working: "
        "only change what is needed to remove the vulnerability."
        f"{rejection_block}\n\n"
        "For every line that must change, provide:\n"
        "  old_stripped: exact stripped content of the original line\n"
        "  new_stripped: replacement stripped content, or null to delete the line\n\n"
        "Return ONLY a JSON object with a 'changes' array."
    )


def _normalize_quotes(s: str) -> str:
    """Normalize escaped vs unescaped quotes for fuzzy line matching."""
    return s.replace('\\"', '"').replace("\\'", "'")


def _find_line_in_source(
    stripped_content: str,
    source_lines: dict[int, str],
    func_range: tuple[int, int],
) -> int | None:
    """Find a line in source_lines whose stripped content matches stripped_content.

    Comparison is done after normalizing escaped quotes so that the model's output
    (which may use `"` or `\"`) matches source lines that may use the other form.
    Returns the 1-based line number, or None if not found.
    """
    normalized = _normalize_quotes(stripped_content)
    start, end = func_range
    for n in range(start, end + 1):
        if n in source_lines and _normalize_quotes(source_lines[n].strip()) == normalized:
            return n
    # Fallback: search full source context
    for n, content in source_lines.items():
        if _normalize_quotes(content.strip()) == normalized:
            return n
    return None


_DELETE_SENTINEL = object()  # marker for "delete this line"


def _construct_diff_from_changes_json(
    raw_json: str,
    file_path: str,
    source_lines: dict[int, str],
    func_range: tuple[int, int],
) -> str:
    """Parse {changes: [{old_stripped, new_stripped|null}, ...]} JSON and build a unified diff.

    Each entry maps an original source line (by stripped+quote-normalized content) to its
    replacement. If new_stripped is null, empty, or omitted the line is DELETED.
    Multiple changes in the same 6-line window are merged into a single hunk.
    """
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"model did not return valid JSON: {exc}") from exc

    changes_raw = parsed.get("changes", [])
    if not changes_raw:
        raise ValueError("JSON missing changes array")

    # Resolve each entry to (lineno, original_source_line, new_content | _DELETE_SENTINEL)
    resolved: list[tuple[int, str, object]] = []
    seen_linenos: set[int] = set()
    for entry in changes_raw:
        old_s: str = entry.get("old_stripped", "")
        if not old_s:
            continue
        new_s = entry.get("new_stripped")  # may be None (delete) or a string (replace)
        lineno = _find_line_in_source(old_s, source_lines, func_range)
        if lineno is None or lineno in seen_linenos:
            continue
        original_line = source_lines[lineno]
        if not new_s:
            # null or empty → delete
            resolved.append((lineno, original_line, _DELETE_SENTINEL))
        else:
            indent = original_line[: len(original_line) - len(original_line.lstrip())]
            new_line = indent + new_s.strip()
            if original_line == new_line:
                continue  # unchanged — skip
            resolved.append((lineno, original_line, new_line))
        seen_linenos.add(lineno)

    if not resolved:
        raise ValueError("no valid changes found in JSON")

    resolved.sort(key=lambda t: t[0])

    # Group adjacent changes (within 2*ctx lines)
    ctx = 3
    groups: list[list[tuple[int, str, object]]] = []
    for change in resolved:
        if groups and change[0] <= groups[-1][-1][0] + 2 * ctx:
            groups[-1].append(change)
        else:
            groups.append([change])

    all_hunk_lines: list[str] = []
    for group in groups:
        first_lineno = group[0][0]
        last_lineno = group[-1][0]
        hunk_start = max(1, first_lineno - ctx)
        hunk_end = min(max(source_lines), last_lineno + ctx)

        change_map: dict[int, object] = {lineno: new for lineno, _, new in group}
        orig_map: dict[int, str] = {lineno: orig for lineno, orig, _ in group}

        hunk_body: list[str] = []
        for n in range(hunk_start, hunk_end + 1):
            if n not in source_lines:
                break
            if n in change_map:
                hunk_body.append(f"-{orig_map[n]}\n")
                if change_map[n] is not _DELETE_SENTINEL:
                    new_content = str(change_map[n])
                    # Models sometimes output literal backslash-n instead of a real newline
                    if "\\n" in new_content and "\n" not in new_content:
                        new_content = new_content.replace("\\n", "\n")
                    if "\n" in new_content:
                        # Multi-line replacement: sub_lines[0] already carries orig_indent
                        # (from indent + new_s.strip() above).  Sub_lines[1:] may carry
                        # either relative (small) or absolute (large) indentation.
                        # Normalize by stripping the minimum common indent from sub_lines[1:]
                        # then prepending orig_indent to reconstruct correct absolute indent.
                        orig_indent = orig_map[n][: len(orig_map[n]) - len(orig_map[n].lstrip())]
                        sub_lines = new_content.split("\n")
                        # Remove trailing empty element from split
                        while sub_lines and not sub_lines[-1].strip():
                            sub_lines.pop()
                        # Compute minimum indent of non-empty continuation lines
                        cont_lines = [sl for sl in sub_lines[1:] if sl.strip()]
                        if cont_lines:
                            min_indent = min(len(sl) - len(sl.lstrip()) for sl in cont_lines)
                        else:
                            min_indent = 0
                        for i, sub_line in enumerate(sub_lines):
                            if i == 0:
                                hunk_body.append(f"+{sub_line}\n")
                            elif not sub_line.strip():
                                hunk_body.append(f"+\n")
                            else:
                                rel = sub_line[min_indent:]  # strip common prefix
                                hunk_body.append(f"+{orig_indent}{rel}\n")
                    else:
                        hunk_body.append(f"+{new_content}\n")
            else:
                hunk_body.append(f" {source_lines[n]}\n")

        while hunk_body and hunk_body[-1].startswith(" ") and hunk_body[-1].strip() == "":
            hunk_body.pop()

        if not any(bl.startswith(("+", "-")) for bl in hunk_body):
            continue

        old_count = sum(1 for bl in hunk_body if not bl.startswith("+"))
        new_count = sum(1 for bl in hunk_body if not bl.startswith("-"))
        old_part = f"{hunk_start}" if old_count == 1 else f"{hunk_start},{old_count}"
        new_part = f"{hunk_start}" if new_count == 1 else f"{hunk_start},{new_count}"
        all_hunk_lines.append(f"@@ -{old_part} +{new_part} @@\n")
        all_hunk_lines.extend(hunk_body)

    if not all_hunk_lines:
        raise ValueError("produced empty diff")

    diff = (
        f"diff --git a/{file_path} b/{file_path}\n"
        f"--- a/{file_path}\n"
        f"+++ b/{file_path}\n"
    )
    diff += "".join(all_hunk_lines)
    return diff


__all__ = ["OllamaModelClient", "OllamaReplacementClient"]
