"""Codex CLI adapter for the model-client boundary.

The adapter invokes an already-authenticated local ``codex`` executable.  It
passes prompts through stdin, runs in an empty temporary workspace, and reads
only Codex's ``--output-last-message`` file as the model response.  The CLI
does not expose a stable billable-dollar value, so callers may assign a
conservative per-invocation accounting cost for framework budget enforcement.
"""

from __future__ import annotations

import asyncio
import math
import os
import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .models import ModelResponse
from .runners import _terminate_process_tree

_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
_SAFE_ENVIRONMENT_NAMES = (
    "APPDATA",
    "CODEX_HOME",
    "COMSPEC",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "WINDIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
)


class CodexCliError(RuntimeError):
    """Codex could not produce a usable model response."""


class CodexBudgetExceeded(ValueError):
    """The configured accounting cost cannot fit in the call budget."""


class CodexTimeoutError(TimeoutError):
    """Codex exceeded its configured wall-clock timeout."""


@dataclass(frozen=True, slots=True)
class CodexInvocation:
    """Fully materialized, shell-free Codex process request."""

    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    output_path: Path
    timeout_seconds: float
    max_stderr_bytes: int
    termination_grace_seconds: float = 1.0


@dataclass(frozen=True, slots=True)
class CodexProcessResult:
    returncode: int
    stderr: str = ""
    stderr_truncated: bool = False


CodexRunner = Callable[[CodexInvocation, str], Awaitable[CodexProcessResult]]


def _default_runner() -> CodexRunner:
    return _run_codex_process


def build_codex_argv(
    executable: str,
    *,
    model_id: str,
    reasoning_effort: str,
    output_path: Path,
) -> tuple[str, ...]:
    """Build the fixed, non-shell ``codex exec`` argv."""

    _validate_text(executable, "executable")
    _validate_text(model_id, "model_id")
    if reasoning_effort not in _REASONING_EFFORTS:
        choices = ", ".join(sorted(_REASONING_EFFORTS))
        raise ValueError(f"reasoning_effort must be one of: {choices}")
    if not output_path.is_absolute():
        raise ValueError("output_path must be absolute")
    return (
        executable,
        "exec",
        "--model",
        model_id,
        "--sandbox",
        "read-only",
        "--ephemeral",
        "--ignore-user-config",
        "--skip-git-repo-check",
        "--color",
        "never",
        "--output-last-message",
        str(output_path),
        "-c",
        f'model_reasoning_effort="{reasoning_effort}"',
        "-",
    )


@dataclass(slots=True)
class CodexCliClient:
    """A :class:`ModelClientProtocol` implementation backed by ``codex exec``.

    ``temperature`` and ``max_tokens`` are validated for protocol compatibility,
    but are not forwarded because ``codex exec`` has no matching stable flags.
    """

    model_id: str = "gpt-5.5"
    reasoning_effort: str = "high"
    executable: str | None = None
    timeout_seconds: float = 120.0
    accounting_cost_usd: float = 0.0
    max_output_bytes: int = 4 * 1024 * 1024
    max_stderr_bytes: int = 32 * 1024
    termination_grace_seconds: float = 1.0
    runner: CodexRunner = field(default_factory=_default_runner, repr=False)

    def __post_init__(self) -> None:
        _validate_text(self.model_id, "model_id")
        if self.reasoning_effort not in _REASONING_EFFORTS:
            choices = ", ".join(sorted(_REASONING_EFFORTS))
            raise ValueError(f"reasoning_effort must be one of: {choices}")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a finite positive number")
        if not math.isfinite(self.accounting_cost_usd) or self.accounting_cost_usd < 0:
            raise ValueError("accounting_cost_usd must be finite and non-negative")
        if self.max_output_bytes <= 0 or self.max_stderr_bytes <= 0:
            raise ValueError("output limits must be positive")
        if (
            not math.isfinite(self.termination_grace_seconds)
            or not 0 <= self.termination_grace_seconds <= 30
        ):
            raise ValueError("termination_grace_seconds must be in [0, 30]")
        if self.executable is not None:
            _validate_text(self.executable, "executable")

    async def complete(
        self,
        prompt: str,
        *,
        temperature: float,
        max_tokens: int,
        max_cost_usd: float,
    ) -> ModelResponse:
        _validate_text(prompt, "prompt", allow_line_breaks=True)
        if not math.isfinite(temperature) or not 0 <= temperature <= 2:
            raise ValueError("temperature must be a finite number in [0, 2]")
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            raise ValueError("max_tokens must be a positive integer")
        if not math.isfinite(max_cost_usd) or max_cost_usd < 0:
            raise ValueError("max_cost_usd must be finite and non-negative")
        if self.accounting_cost_usd > max_cost_usd:
            raise CodexBudgetExceeded("Codex accounting cost exceeds the remaining per-call budget")

        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="vulnrepair-codex-") as temporary:
            workspace = Path(temporary).resolve()
            output_path = workspace / "last-message.txt"
            executable = _resolve_executable(self.executable)
            invocation = CodexInvocation(
                argv=build_codex_argv(
                    executable,
                    model_id=self.model_id,
                    reasoning_effort=self.reasoning_effort,
                    output_path=output_path,
                ),
                cwd=workspace,
                environment=_codex_environment(),
                output_path=output_path,
                timeout_seconds=self.timeout_seconds,
                max_stderr_bytes=self.max_stderr_bytes,
                termination_grace_seconds=self.termination_grace_seconds,
            )
            result = await self.runner(invocation, prompt)
            if result.returncode != 0:
                detail = f": {result.stderr}" if result.stderr else ""
                raise CodexCliError(f"codex exec exited with status {result.returncode}{detail}")
            text = _read_last_message(output_path, self.max_output_bytes)

        return ModelResponse(
            text=text,
            model_id=self.model_id,
            cost_usd=self.accounting_cost_usd,
            latency_seconds=time.monotonic() - started,
        )


async def _run_codex_process(invocation: CodexInvocation, prompt: str) -> CodexProcessResult:
    """Default process seam; tests may inject a runner without starting Codex."""

    try:
        if os.name == "nt":
            process = await asyncio.create_subprocess_exec(
                *invocation.argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(invocation.cwd),
                env=dict(invocation.environment),
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
            )
        else:
            process = await asyncio.create_subprocess_exec(
                *invocation.argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(invocation.cwd),
                env=dict(invocation.environment),
                start_new_session=True,
            )
    except OSError as exc:
        raise CodexCliError(f"could not start codex exec: {exc}") from exc

    if process.stdin is None or process.stderr is None:
        await _finish_process_cleanup(process, (), invocation.termination_grace_seconds)
        raise CodexCliError("codex process pipes were not created")

    feed_task = asyncio.create_task(_feed_stdin(process.stdin, prompt))
    stderr_task = asyncio.create_task(_drain_stderr(process.stderr, invocation.max_stderr_bytes))
    wait_task = asyncio.create_task(process.wait())
    tasks: tuple[asyncio.Task[object], ...] = (feed_task, stderr_task, wait_task)
    try:
        async with asyncio.timeout(invocation.timeout_seconds):
            returncode = await wait_task
            await feed_task
            stderr_bytes, truncated = await stderr_task
    except TimeoutError as exc:
        await _finish_process_cleanup(process, tasks, invocation.termination_grace_seconds)
        raise CodexTimeoutError(
            f"codex exec exceeded {invocation.timeout_seconds:g} seconds"
        ) from exc
    except asyncio.CancelledError:
        await _finish_process_cleanup(process, tasks, invocation.termination_grace_seconds)
        raise
    except Exception as exc:
        await _finish_process_cleanup(process, tasks, invocation.termination_grace_seconds)
        raise CodexCliError(f"codex process I/O failed: {exc}") from exc

    return CodexProcessResult(
        returncode=returncode,
        stderr=_clean_stderr(stderr_bytes),
        stderr_truncated=truncated,
    )


async def _feed_stdin(writer: asyncio.StreamWriter, prompt: str) -> None:
    try:
        writer.write(prompt.encode("utf-8"))
        await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def _drain_stderr(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    retained = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            return bytes(retained), truncated
        remaining = limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            truncated = True


async def _finish_process_cleanup(
    process: asyncio.subprocess.Process,
    tasks: tuple[asyncio.Task[object], ...],
    grace_seconds: float,
) -> None:
    cleanup = asyncio.create_task(_terminate_process_tree(process, grace_seconds))
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            continue
    try:
        cleanup.result()
    except Exception:
        pass
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


def _resolve_executable(configured: str | None) -> str:
    selected = configured or "codex"
    found = shutil.which(selected)
    if found is None:
        candidate = Path(selected).expanduser()
        if not candidate.is_absolute():
            raise CodexCliError("codex executable was not found on PATH")
        try:
            candidate = candidate.resolve(strict=True)
        except OSError as exc:
            raise CodexCliError(f"codex executable is unavailable: {exc}") from exc
        if not candidate.is_file():
            raise CodexCliError("codex executable is not a file")
        found = str(candidate)
    return str(Path(found).resolve())


def _codex_environment() -> dict[str, str]:
    environment = {
        name: value for name in _SAFE_ENVIRONMENT_NAMES if (value := os.environ.get(name))
    }
    environment.setdefault("LANG", "C.UTF-8" if os.name != "nt" else "C")
    environment["NO_COLOR"] = "1"
    environment["TERM"] = "dumb"
    return environment


def _read_last_message(path: Path, limit: int) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CodexCliError("codex did not write its last-message file") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CodexCliError("codex last-message output is not a regular file")
    if metadata.st_size <= 0:
        raise CodexCliError("codex returned an empty response")
    if metadata.st_size > limit:
        raise CodexCliError("codex response exceeded the configured output limit")
    try:
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CodexCliError("codex response is not valid UTF-8 text") from exc
    if not value.strip():
        raise CodexCliError("codex returned an empty response")
    return value


def _clean_stderr(value: bytes) -> str:
    decoded = value.decode("utf-8", errors="replace")
    return "".join(
        character for character in decoded if character in "\n\r\t" or ord(character) >= 32
    ).strip()


def _validate_text(value: object, name: str, *, allow_line_breaks: bool = False) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be non-empty text without NUL bytes")
    if not allow_line_breaks and any(character in value for character in "\r\n"):
        raise ValueError(f"{name} must not contain line breaks")


__all__ = [
    "CodexBudgetExceeded",
    "CodexCliClient",
    "CodexCliError",
    "CodexInvocation",
    "CodexProcessResult",
    "CodexRunner",
    "CodexTimeoutError",
    "build_codex_argv",
]
