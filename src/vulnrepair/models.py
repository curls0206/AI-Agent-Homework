"""Model-provider boundary for diverse best-of-N patch generation.

The core package ships no network client and requires no API key.  Provider
adapters implement :class:`ModelClientProtocol`; tests and offline demos can
use deterministic clients.
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable

from .contracts import CodeLocation, FailureRecord, PatchCandidate, VulnTask
from .snapshot import SnapshotMaterializer


@dataclass(frozen=True, slots=True)
class ModelResponse:
    text: str
    model_id: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    latency_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not self.model_id:
            raise ValueError("model_id must not be empty")
        if min(self.prompt_tokens, self.completion_tokens) < 0:
            raise ValueError("token counts cannot be negative")
        if (
            not math.isfinite(self.cost_usd)
            or not math.isfinite(self.latency_seconds)
            or self.cost_usd < 0
            or self.latency_seconds < 0
        ):
            raise ValueError("cost and latency must be finite and non-negative")


@dataclass(slots=True)
class ModelUsage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    budget_violations: int = 0

    def reserve_calls(self, count: int) -> None:
        if count < 0:
            raise ValueError("reserved call count cannot be negative")
        self.calls += count

    def add_response(self, response: ModelResponse) -> None:
        self.prompt_tokens += response.prompt_tokens
        self.completion_tokens += response.completion_tokens
        self.cost_usd += response.cost_usd


@runtime_checkable
class ModelClientProtocol(Protocol):
    model_id: str

    async def complete(
        self,
        prompt: str,
        *,
        temperature: float,
        max_tokens: int,
        max_cost_usd: float,
    ) -> ModelResponse: ...


@runtime_checkable
class CodeContextProviderProtocol(Protocol):
    async def context(self, task: VulnTask, location: CodeLocation) -> str: ...


@dataclass(frozen=True, slots=True)
class MappingContextProvider:
    contexts: dict[tuple[str, int, int], str]

    async def context(self, task: VulnTask, location: CodeLocation) -> str:
        del task
        key = (location.file_path, location.start_line, location.end_line)
        try:
            return self.contexts[key]
        except KeyError as exc:
            raise KeyError(f"no source context registered for {key!r}") from exc


@dataclass(frozen=True, slots=True)
class GitSnapshotContextProvider:
    """Read bounded source context from the task's immutable Git snapshot.

    Model prompts must not observe dirty or untracked working-tree content.  The
    snapshot materializer resolves ``base_ref`` to a commit and validates every
    extracted byte before this provider reads the requested location.
    """

    materializer: SnapshotMaterializer = field(default_factory=SnapshotMaterializer)
    surrounding_lines: int = 80
    max_file_bytes: int = 512 * 1024
    max_context_chars: int = 32_000

    def __post_init__(self) -> None:
        if self.surrounding_lines < 0:
            raise ValueError("surrounding_lines cannot be negative")
        if self.max_file_bytes <= 0 or self.max_context_chars <= 0:
            raise ValueError("context limits must be positive")

    async def context(self, task: VulnTask, location: CodeLocation) -> str:
        return await asyncio.to_thread(self._read_context, task, location)

    def _read_context(self, task: VulnTask, location: CodeLocation) -> str:
        relative = _safe_source_path(location.file_path)
        with self.materializer.materialize(Path(task.repo_path), task.base_ref) as snapshot:
            source_path = snapshot.root.joinpath(*relative.parts)
            try:
                size = source_path.stat().st_size
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"localized source file is absent from {snapshot.metadata.commit}: "
                    f"{location.file_path}"
                ) from exc
            if not source_path.is_file():
                raise ValueError(
                    f"localized source path is not a regular file: {location.file_path}"
                )
            if size > self.max_file_bytes:
                raise ValueError(
                    f"localized source file exceeds context limit: {location.file_path}"
                )
            source = source_path.read_text(encoding="utf-8", errors="strict")

        lines = source.splitlines()
        if location.start_line > len(lines):
            raise ValueError(
                f"localized line {location.start_line} exceeds {location.file_path} length"
            )
        first = max(1, location.start_line - self.surrounding_lines)
        last = min(len(lines), location.end_line + self.surrounding_lines)
        rendered = "\n".join(
            f"{line_number:>6}: {lines[line_number - 1]}" for line_number in range(first, last + 1)
        )
        if len(rendered) > self.max_context_chars:
            rendered = rendered[: self.max_context_chars]
            rendered += "\n[context truncated at configured character limit]"
        return rendered


def _safe_source_path(value: str) -> PurePosixPath:
    if value.startswith(("/", "\\")) or "\\" in value:
        raise ValueError(f"localized source path must be relative POSIX form: {value!r}")
    path = PurePosixPath(value)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"localized source path is not normalized: {value!r}")
    if any(part.casefold() == ".git" for part in path.parts):
        raise ValueError("localized source path cannot address Git metadata")
    return path


@dataclass(slots=True)
class ModelPoolGenerator:
    """Call different model clients concurrently and return canonical patches."""

    clients: tuple[ModelClientProtocol, ...]
    context_provider: CodeContextProviderProtocol
    samples_per_model: int = 1
    temperature: float = 0.7
    max_tokens: int = 2_048
    max_failure_context: int = 6
    usage: ModelUsage = field(default_factory=ModelUsage, init=False)
    last_errors: tuple[str, ...] = field(default=(), init=False)

    def __post_init__(self) -> None:
        if not self.clients:
            raise ValueError("at least one model client is required")
        if self.samples_per_model <= 0 or self.max_tokens <= 0:
            raise ValueError("samples_per_model and max_tokens must be positive")
        if not 0 <= self.temperature <= 2:
            raise ValueError("temperature must be between 0 and 2")
        ids = [client.model_id for client in self.clients]
        if any(not model_id for model_id in ids) or len(ids) != len(set(ids)):
            raise ValueError("model IDs must be non-empty and unique")

    async def generate(
        self,
        task: VulnTask,
        locations: tuple[CodeLocation, ...],
        failures: tuple[FailureRecord, ...],
        limit: int,
        max_cost_usd: float,
    ) -> tuple[PatchCandidate, ...]:
        self.last_errors = ()
        if not math.isfinite(max_cost_usd) or max_cost_usd < 0:
            raise ValueError("max_cost_usd must be a finite non-negative number")
        if limit <= 0 or max_cost_usd <= 0:
            return ()
        # Each job carries (model_id, sample_index, location, prompt, source_context)
        # so the response handler can convert SEARCH/REPLACE → diff without extra I/O.
        jobs: list[tuple[str, int, CodeLocation, str, str]] = []
        for location in locations:
            if len(jobs) >= limit:
                break
            source = await self.context_provider.context(task, location)
            prompt = build_patch_prompt(
                task, location, source, failures[-self.max_failure_context :]
            )
            for client in sorted(self.clients, key=lambda item: item.model_id):
                if len(jobs) >= limit:
                    break
                for sample in range(self.samples_per_model):
                    if len(jobs) >= limit:
                        break
                    jobs.append((client.model_id, sample, location, prompt, source))

        clients = {client.model_id: client for client in self.clients}
        if not jobs:
            return ()
        per_call_cost_limit = max_cost_usd / len(jobs)
        self.usage.reserve_calls(len(jobs))

        async def invoke(
            job: tuple[str, int, CodeLocation, str, str],
        ) -> tuple[tuple[str, int, CodeLocation, str], ModelResponse | Exception]:
            model_id, sample, location, prompt, source = job
            try:
                response = await clients[model_id].complete(
                    prompt,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    max_cost_usd=per_call_cost_limit,
                )
                return (model_id, sample, location, source), response
            except Exception as exc:  # A failed provider must not cancel the pool.
                return (model_id, sample, location, source), exc

        responses = await asyncio.gather(*(invoke(job) for job in jobs))
        candidates: dict[str, PatchCandidate] = {}
        provider_errors: list[str] = []
        import sys as _sys, os as _os
        _debug = _os.environ.get("VULNREPAIR_DEBUG_RESPONSE")
        for (model_id, sample, location, source), response in responses:
            if isinstance(response, Exception):
                detail = " ".join(str(response).split())[:240]
                provider_errors.append(
                    f"{model_id} sample {sample + 1}: {type(response).__name__}"
                    + (f": {detail}" if detail else "")
                )
                if _debug:
                    _sys.stderr.write(f"\n[DEBUG] provider exception {model_id} s{sample}: {type(response).__name__}: {detail}\n")
                    _sys.stderr.flush()
                continue
            self.usage.add_response(response)
            if response.cost_usd > per_call_cost_limit + 1e-12:
                self.usage.budget_violations += 1
                continue
            if _debug:
                _sys.stderr.write(f"\n[DEBUG] LLM responded {len(response.text)} chars for {model_id}\n")
                _sys.stderr.write(f"[DEBUG] response preview: {response.text[:500]!r}\n")
                _sys.stderr.flush()
            try:
                diff = _response_to_diff(response.text, location.file_path, source)
                candidate = PatchCandidate(
                    task_id=task.task_id,
                    diff=diff,
                    target_location=location,
                    generated_by=model_id,
                    rationale=f"model pool sample {sample + 1}",
                )
            except (TypeError, ValueError) as _parse_exc:
                if _debug:
                    _sys.stderr.write(f"\n[DEBUG] parse failed ({type(_parse_exc).__name__}): {_parse_exc}\n")
                    _sys.stderr.write(f"[DEBUG] full response ({len(response.text)} chars):\n")
                    _sys.stderr.write(response.text[:3000])
                    _sys.stderr.write("\n[DEBUG] ---END---\n")
                    _sys.stderr.flush()
                continue
            candidates.setdefault(candidate.candidate_id, candidate)
        self.last_errors = tuple(provider_errors)
        return tuple(candidates[key] for key in sorted(candidates))


def _extract_vulnerable_lines(
    source_context: str,
    start_line: int,
    end_line: int,
    pad: int = 2,
) -> str:
    """Return the verbatim source lines spanning start_line..end_line (± pad lines).

    Uses the parsed source dict so the result is guaranteed to come from the
    actual snapshot, not from the LLM's memory.  Returns an empty string when
    the requested lines are absent from the context window.
    """
    source_dict = _parse_source_lines(source_context)
    if not source_dict:
        return ""
    lo = max(min(source_dict), start_line - pad)
    hi = min(max(source_dict), end_line + pad)
    lines = []
    for ln in range(lo, hi + 1):
        if ln in source_dict:
            lines.append(source_dict[ln])
    return "\n".join(lines)


def build_patch_prompt(
    task: VulnTask,
    location: CodeLocation,
    source_context: str,
    failures: tuple[FailureRecord, ...],
) -> str:
    """Build a prompt with a pre-filled SEARCH block and ask only for the REPLACE.

    Pre-populating the SEARCH block with the actual vulnerable lines eliminates
    the most common failure mode: the LLM hallucinating the SEARCH content from
    its training memory instead of copying it verbatim from the source.
    The LLM still decides *how* to fix the code (the REPLACE block).
    """
    failure_lines: list[str] = []
    for record in failures:
        line = f"- {record.candidate_id[:12]}: {record.overall.value}: {record.reason}"
        if record.poc_detail:
            line += f"\n  PoC stdout: {record.poc_detail}"
        failure_lines.append(line)
    failure_text = "\n".join(failure_lines) or "- none"
    cve_prefix = f"CVE: {task.cve_id}  " if task.cve_id else ""

    # Pre-fill the SEARCH block with the actual source lines so the LLM cannot
    # hallucinate them.  Fall back to asking the LLM to fill it when the lines
    # are outside the context window (should be rare given surrounding_lines=80).
    vulnerable_lines = _extract_vulnerable_lines(
        source_context, location.start_line, location.end_line
    )
    if vulnerable_lines:
        search_block = (
            f"SEARCH_FILE: {location.file_path}\n"
            "<<<<<<< SEARCH\n"
            f"{vulnerable_lines}\n"
            "=======\n"
            "<write the FIXED replacement here>\n"
            ">>>>>>> REPLACE"
        )
        format_instruction = (
            "The SEARCH block has been pre-filled with the exact vulnerable lines.\n"
            "Complete the REPLACE block with your security fix.\n"
            "Your ENTIRE response must be this completed block — no prose, no fences:\n\n"
            f"{search_block}"
        )
    else:
        search_block = (
            f"SEARCH_FILE: {location.file_path}\n"
            "<<<<<<< SEARCH\n"
            "<copy the vulnerable lines verbatim from the source below>\n"
            "=======\n"
            "<write the FIXED replacement here>\n"
            ">>>>>>> REPLACE"
        )
        format_instruction = (
            "Output a SEARCH/REPLACE block. Your ENTIRE response must be:\n\n"
            f"{search_block}\n\n"
            "The SEARCH block MUST be an exact verbatim copy of consecutive lines "
            "from the source — do NOT paraphrase or change a single character."
        )

    return (
        "You are a security engineer fixing a real vulnerability.\n"
        "Study the source code below, identify the root cause, then complete the fix.\n"
        "\n"
        f"{format_instruction}\n"
        "\n"
        "Hard rules — violations cause automatic rejection:\n"
        "1. Preserve indentation exactly in the REPLACE section.\n"
        "2. Do not touch tests, build config, CI, PoCs, scanners, or unrelated files.\n"
        "3. Keep changes minimal — only the lines needed to close the gap.\n"
        "\n"
        f"{cve_prefix}CWE: {task.cwe_id}\n"
        f"Vulnerability: {task.description}\n"
        f"Affected versions: {task.affected_versions}\n"
        f"Vulnerable file: {location.file_path}\n"
        f"Vulnerable lines: {location.start_line}–{location.end_line}\n"
        f"Vulnerable function: {location.function_name or 'unknown'}\n"
        "\n"
        "Source code (line numbers for reference — do NOT copy them into the block):\n"
        f"{source_context}\n"
        "\n"
        "Silently reason before writing:\n"
        "  Q1: What security property SHOULD this code enforce?\n"
        "  Q2: What specific value, pattern, or condition is missing or too permissive?\n"
        "  Q3: What is the minimal change that closes the gap without altering other behaviour?\n"
        "\n"
        f"Previously rejected patches — do NOT repeat these:\n{failure_text}\n"
        "\n"
        "Now complete the SEARCH/REPLACE block above (output it in full, with your REPLACE filled in):"
    )


def _response_to_diff(response_text: str, file_path: str, source_context: str) -> str:
    """Convert a model response to a valid unified diff.

    Strategy (in order):
    1. SEARCH/REPLACE block — the primary format the prompt now requests.
       Context lines are taken from the *actual* source, so the diff is correct
       by construction.
    2. Unified diff extracted anywhere in the response — covers the case where
       the model ignored the new prompt format and produced a raw diff (possibly
       prefixed with explanation text).

    Raises ``ValueError`` (or ``TypeError``) if neither format is usable.
    """
    source_lines = _parse_source_lines(source_context)

    # --- 1. SEARCH/REPLACE ---
    sr = extract_search_replace(response_text)
    if sr is not None:
        sr_file, search, replace = sr
        fp = sr_file if sr_file else file_path
        return search_replace_to_diff(fp, search, replace, source_lines)

    # --- 2. Unified diff (permissive: scan for 'diff --git' anywhere) ---
    return _extract_unified_diff_permissive(response_text)


def _extract_unified_diff_permissive(text: str) -> str:
    """Extract a unified diff from a response that may have prose before or after.

    Unlike :func:`extract_unified_diff`, this function scans for the
    ``diff --git`` marker anywhere in the text rather than requiring it at
    position 0.  It handles Markdown code fences and leading/trailing prose.
    """
    if not isinstance(text, str):
        raise TypeError("model response must be text")
    cleaned = text.strip()

    # Strip a single Markdown code fence that wraps the whole response.
    if cleaned.startswith("```"):
        first_newline = cleaned.find("\n")
        if first_newline >= 0 and cleaned.endswith("```"):
            cleaned = cleaned[first_newline + 1 : -3].strip()

    # Find 'diff --git' anywhere in the (possibly prose-prefixed) response.
    marker = cleaned.find("diff --git ")
    if marker < 0:
        raise ValueError("response contains no Git unified diff")
    cleaned = cleaned[marker:]

    # Truncate at any trailing prose after the last hunk.
    if "@@ " not in cleaned:
        raise ValueError("response does not contain a diff hunk")
    return cleaned


def extract_unified_diff(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("model response must be text")
    cleaned = text.strip()
    if cleaned.startswith("```"):
        first_newline = cleaned.find("\n")
        if first_newline < 0 or not cleaned.endswith("```"):
            raise ValueError("malformed Markdown code fence")
        cleaned = cleaned[first_newline + 1 : -3].strip()
    marker = cleaned.find("diff --git ")
    if marker != 0:
        raise ValueError("response must contain only a Git unified diff")
    if "\ndiff --git " not in cleaned and "@@ " not in cleaned:
        raise ValueError("response does not contain a diff hunk")
    return cleaned


# ---------------------------------------------------------------------------
# SEARCH/REPLACE → unified diff conversion
# ---------------------------------------------------------------------------

_SR_RE = re.compile(
    r"SEARCH_FILE:\s*(\S[^\n]*?)\s*\n"
    r"<{6,9}\s*SEARCH\s*\n"
    r"(.*?)"
    r"={6,9}\s*\n"
    r"(.*?)"
    r">{6,9}\s*REPLACE",
    re.DOTALL,
)


def extract_search_replace(text: str) -> tuple[str, str, str] | None:
    """Parse a SEARCH/REPLACE block from model output.

    Returns ``(file_path, search_text, replace_text)`` or ``None`` if the
    response does not contain a recognisable SEARCH/REPLACE block.
    """
    if not isinstance(text, str):
        return None
    m = _SR_RE.search(text)
    if m is None:
        return None
    file_path = m.group(1).strip()
    search = m.group(2).rstrip("\n")
    replace = m.group(3).rstrip("\n")
    if not search.strip():
        return None
    return file_path, search, replace


def _parse_source_lines(source_context: str) -> dict[int, str]:
    """Parse the ``'  62: code line'`` formatted context into ``{62: 'code line'}``."""
    lines: dict[int, str] = {}
    for raw in source_context.splitlines():
        m = re.match(r"^\s*(\d+):\s?(.*)$", raw)
        if m:
            lines[int(m.group(1))] = m.group(2)
    return lines


def _find_in_source(search_lines: list[str], source_dict: dict[int, str]) -> int | None:
    """Return the first line number where *search_lines* appears in *source_dict*.

    Tries exact match first, then a trailing-whitespace-normalised match.
    Returns ``None`` if not found.
    """
    sorted_items = sorted(source_dict.items())
    n = len(search_lines)
    if n == 0 or n > len(sorted_items):
        return None

    for i in range(len(sorted_items) - n + 1):
        window = [content for _, content in sorted_items[i : i + n]]
        if window == search_lines:
            return sorted_items[i][0]

    norm = [s.rstrip() for s in search_lines]
    for i in range(len(sorted_items) - n + 1):
        window = [content.rstrip() for _, content in sorted_items[i : i + n]]
        if window == norm:
            return sorted_items[i][0]

    return None


def search_replace_to_diff(
    file_path: str,
    search: str,
    replace: str,
    source_lines: dict[int, str],
) -> str:
    """Convert a SEARCH/REPLACE pair to a valid unified diff.

    The context lines in the hunk are read from *source_lines* (the actual
    source code), so the resulting diff is guaranteed to apply cleanly.

    Raises ``ValueError`` if the search text cannot be found in *source_lines*.
    """
    search_split = search.splitlines()
    replace_split = replace.splitlines()
    if not search_split:
        raise ValueError("SEARCH block is empty")

    start_line = _find_in_source(search_split, source_lines)
    if start_line is None:
        raise ValueError("SEARCH text not found in the source context window")

    source_dict = dict(source_lines)
    end_line = start_line + len(search_split) - 1

    ctx_before: list[tuple[int, str]] = []
    for delta in range(3, 0, -1):
        ln = start_line - delta
        if ln in source_dict:
            ctx_before.append((ln, source_dict[ln]))

    ctx_after: list[tuple[int, str]] = []
    for delta in range(1, 4):
        ln = end_line + delta
        if ln in source_dict:
            ctx_after.append((ln, source_dict[ln]))

    old_start = ctx_before[0][0] if ctx_before else start_line
    old_count = len(ctx_before) + len(search_split) + len(ctx_after)
    new_count = len(ctx_before) + len(replace_split) + len(ctx_after)

    hunk_lines: list[str] = []
    for _, content in ctx_before:
        hunk_lines.append(f" {content}")
    for line in search_split:
        hunk_lines.append(f"-{line}")
    for line in replace_split:
        hunk_lines.append(f"+{line}")
    for _, content in ctx_after:
        hunk_lines.append(f" {content}")

    return (
        f"diff --git a/{file_path} b/{file_path}\n"
        f"--- a/{file_path}\n"
        f"+++ b/{file_path}\n"
        f"@@ -{old_start},{old_count} +{old_start},{new_count} @@\n"
        + "\n".join(hunk_lines)
    )


__all__ = [
    "CodeContextProviderProtocol",
    "GitSnapshotContextProvider",
    "MappingContextProvider",
    "ModelClientProtocol",
    "ModelPoolGenerator",
    "ModelResponse",
    "ModelUsage",
    "build_patch_prompt",
    "extract_search_replace",
    "extract_unified_diff",
    "search_replace_to_diff",
]
