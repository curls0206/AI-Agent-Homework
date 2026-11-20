"""Bounded command runners for trusted local fixtures and Docker sandboxes."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Awaitable, Iterable, Mapping, Sequence, TypeVar

from .contracts import CommandResult, CommandSpec, StageVerdict

if os.name == "nt":
    from ._windows_job import WindowsJob
else:
    WindowsJob = None  # type: ignore[assignment,misc]

_SENSITIVE_ENV_RE = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|AUTH|BEARER|COOKIE|SESSION|CERT)",
    re.I,
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIGEST_REFERENCE_RE = re.compile(r"^[a-z0-9][a-z0-9._/:+-]*@sha256:[0-9a-f]{64}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class RunnerLimits:
    max_output_bytes: int = 1_048_576
    drain_timeout_seconds: float = 2.0
    termination_grace_seconds: float = 1.0

    def __post_init__(self) -> None:
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if not 0 < self.drain_timeout_seconds <= 30:
            raise ValueError("drain_timeout_seconds must be in (0, 30]")
        if not 0 <= self.termination_grace_seconds <= 30:
            raise ValueError("termination_grace_seconds must be in [0, 30]")


@dataclass(frozen=True, slots=True)
class DockerLimits:
    user: str = field(default_factory=lambda: _default_docker_user())
    pids_limit: int = 64
    memory_bytes: int = 512 * 1024 * 1024
    cpus: float = 1.0
    tmpfs_bytes: int = 64 * 1024 * 1024
    cleanup_timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        match = re.fullmatch(r"([1-9][0-9]*):([1-9][0-9]*)", self.user)
        if not match:
            raise ValueError("Docker user must be a non-root numeric uid:gid")
        if self.pids_limit <= 0 or self.memory_bytes <= 0 or self.tmpfs_bytes <= 0:
            raise ValueError("Docker resource limits must be positive")
        if not 0 < self.cpus <= 64:
            raise ValueError("cpus must be in (0, 64]")
        if not 0 < self.cleanup_timeout_seconds <= 120:
            raise ValueError("cleanup_timeout_seconds must be in (0, 120]")


class LocalCommandRunner:
    """Local execution for trusted fixtures only.

    This runner deliberately refuses to execute unless the caller supplies the
    explicit ``allow_unsafe=True`` opt-in.  It is not a security sandbox.
    """

    def __init__(
        self,
        *,
        allow_unsafe: bool = False,
        limits: RunnerLimits | None = None,
        environment: Mapping[str, str] | None = None,
        redact_values: Iterable[str] = (),
    ) -> None:
        self.allow_unsafe = allow_unsafe
        self.limits = limits or RunnerLimits()
        self.environment = _sanitized_environment(environment)
        self.redact_values = _redaction_values(redact_values, environment)

    async def run(self, spec: CommandSpec, workspace: Path) -> CommandResult:
        if not self.allow_unsafe:
            return _result(
                spec,
                StageVerdict.INFRA_ERROR,
                reason_code="local_execution_disabled",
                stderr="Local execution requires allow_unsafe=True and is only for trusted fixtures.",
            )
        try:
            argv = _validate_argv(spec.argv)
            cwd = _resolve_cwd(workspace, spec.cwd)
        except ValueError as exc:
            return _result(
                spec,
                StageVerdict.INFRA_ERROR,
                reason_code="invalid_command",
                stderr=str(exc),
            )
        return await _execute_process(
            spec,
            argv,
            cwd=cwd,
            env=self.environment,
            limits=self.limits,
            redact_values=self.redact_values,
        )


class DockerCommandRunner:
    """Execute commands in an ephemeral, hardened OCI container (Docker CLI syntax)."""

    engine_name = "docker"
    engine_env_passthrough: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        image: str,
        docker_executable: str | None = None,
        harness_dir: Path | None = None,
        limits: RunnerLimits | None = None,
        docker_limits: DockerLimits | None = None,
        container_environment: Mapping[str, str] | None = None,
        redact_values: Iterable[str] = (),
    ) -> None:
        _validate_immutable_image(image)
        docker = docker_executable or shutil.which(self.engine_name)
        if not docker:
            raise ValueError(f"{self.engine_name} executable is not available")
        docker_path = Path(docker).resolve()
        if not docker_path.is_file():
            raise ValueError(f"{self.engine_name} executable is not a file: {docker_path}")
        self.image = image
        self.docker_executable = str(docker_path)
        self.harness_dir = Path(harness_dir).resolve(strict=True) if harness_dir else None
        if self.harness_dir is not None and not self.harness_dir.is_dir():
            raise ValueError("harness_dir must be a directory")
        self.limits = limits or RunnerLimits()
        self.docker_limits = docker_limits or DockerLimits()
        fixed_environment = {
            "HOME": "/tmp",
            "TMPDIR": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
        }
        fixed_environment.update(_validated_explicit_environment(container_environment))
        self.container_environment = fixed_environment
        self.host_environment = _sanitized_environment(None)
        for name in self.engine_env_passthrough:
            value = os.environ.get(name)
            if value:
                self.host_environment[name] = value
        self.redact_values = _redaction_values(redact_values, container_environment)

    async def run(self, spec: CommandSpec, workspace: Path) -> CommandResult:
        try:
            _validate_argv(spec.argv)
            root = Path(workspace).resolve(strict=True)
            if not root.is_dir():
                raise ValueError("workspace must be a directory")
            _prepare_workspace_for_container(root, self.docker_limits.user)
            relative_cwd = _validate_relative_cwd(spec.cwd)
            _resolve_cwd(root, spec.cwd)
            if "," in str(root) or self.harness_dir is not None and "," in str(self.harness_dir):
                raise ValueError("Docker bind source paths containing commas are not supported")
        except (OSError, ValueError) as exc:
            return _result(
                spec,
                StageVerdict.INFRA_ERROR,
                reason_code="invalid_command",
                stderr=str(exc),
            )

        container_name = f"vulnrepair-{os.getpid()}-{uuid.uuid4().hex[:16]}"
        argv = self._build_docker_argv(spec, root, relative_cwd, container_name)
        try:
            result = await _execute_process(
                spec,
                argv,
                cwd=Path(self.docker_executable).parent,
                env=self.host_environment,
                limits=self.limits,
                redact_values=self.redact_values,
            )
        except asyncio.CancelledError:
            try:
                await _await_cleanup(self._force_remove(container_name))
            except Exception:
                # Cancellation must propagate even if best-effort Docker cleanup fails.
                pass
            raise
        if result.verdict is StageVerdict.FAIL and result.returncode in {125, 126, 127, 137, 143}:
            reasons = {
                125: f"{self.engine_name}_run_error",
                126: "container_command_not_executable",
                127: "container_command_missing",
                137: "container_resource_termination",
                143: "container_termination",
            }
            result = _result(
                spec,
                StageVerdict.INFRA_ERROR,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_seconds=result.duration_seconds,
                truncated=result.truncated,
                reason_code=reasons[result.returncode],
            )
        if result.verdict in {StageVerdict.TIMEOUT, StageVerdict.INFRA_ERROR}:
            cleanup = await _await_cleanup(self._force_remove(container_name))
            if cleanup is not None:
                suffix = f"\nDocker forced cleanup failed: {cleanup}".strip()
                return _result(
                    spec,
                    result.verdict,
                    returncode=result.returncode,
                    stdout=result.stdout,
                    stderr=(result.stderr + "\n" + suffix).strip(),
                    duration_seconds=result.duration_seconds,
                    truncated=result.truncated,
                    reason_code=f"{self.engine_name}_cleanup_failed",
                )
        return result

    def _build_docker_argv(
        self,
        spec: CommandSpec,
        workspace: Path,
        relative_cwd: PurePosixPath,
        container_name: str,
    ) -> tuple[str, ...]:
        workdir = "/workspace"
        if str(relative_cwd) != ".":
            workdir += "/" + relative_cwd.as_posix()
        arguments: list[str] = [
            self.docker_executable,
            "run",
            "--rm",
            "--pull=never",
            "--name",
            container_name,
            "--init",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(self.docker_limits.pids_limit),
            "--memory",
            str(self.docker_limits.memory_bytes),
            "--cpus",
            str(self.docker_limits.cpus),
            "--user",
            self.docker_limits.user,
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={self.docker_limits.tmpfs_bytes}",
            "--workdir",
            workdir,
            "--mount",
            f"type=bind,src={workspace},dst=/workspace",
        ]
        if self.harness_dir is not None:
            arguments.extend(
                (
                    "--mount",
                    f"type=bind,src={self.harness_dir},dst=/harness,readonly",
                )
            )
        for name, value in sorted(self.container_environment.items()):
            arguments.extend(("--env", f"{name}={value}"))
        arguments.append(self.image)
        arguments.extend(spec.argv)
        return tuple(arguments)

    async def _force_remove(self, container_name: str) -> str | None:
        cleanup_spec = CommandSpec(
            name=f"{self.engine_name}-cleanup",
            argv=(self.docker_executable, "rm", "-f", container_name),
            timeout_seconds=self.docker_limits.cleanup_timeout_seconds,
            required=True,
        )
        cleanup_limits = RunnerLimits(
            max_output_bytes=min(self.limits.max_output_bytes, 16_384),
            drain_timeout_seconds=self.limits.drain_timeout_seconds,
            termination_grace_seconds=self.limits.termination_grace_seconds,
        )
        result = await _execute_process(
            cleanup_spec,
            cleanup_spec.argv,
            cwd=Path(self.docker_executable).parent,
            env=self.host_environment,
            limits=cleanup_limits,
            redact_values=(),
        )
        if result.verdict is StageVerdict.PASS:
            return None
        return result.stderr or result.stdout or result.reason_code


class PodmanCommandRunner(DockerCommandRunner):
    """Same hardened sandbox as DockerCommandRunner, executed with the Podman CLI."""

    engine_name = "podman"
    engine_env_passthrough = (
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_RUNTIME_DIR",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
    )


@dataclass(slots=True)
class _OutputBudget:
    limit: int
    used: int = 0
    truncated: bool = False

    def retain(self, chunk: bytes) -> bytes:
        remaining = max(0, self.limit - self.used)
        retained = chunk[:remaining]
        self.used += len(retained)
        if len(retained) != len(chunk):
            self.truncated = True
        return retained


async def _execute_process(
    spec: CommandSpec,
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    limits: RunnerLimits,
    redact_values: Iterable[str],
) -> CommandResult:
    started = time.monotonic()
    windows_job: WindowsJob | None = None
    try:
        if os.name == "nt":
            barrier = Path(__file__).with_name("_windows_job.py").resolve(strict=True)
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                str(barrier),
                *argv,
                cwd=str(cwd),
                env=dict(env),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
            assert WindowsJob is not None and process.stdin is not None
            try:
                windows_job = WindowsJob()
                windows_job.assign_pid(process.pid)
                process.stdin.write(b"\x00")
                await process.stdin.drain()
                process.stdin.close()
                await process.stdin.wait_closed()
            except asyncio.CancelledError:
                try:
                    await _await_cleanup(
                        _terminate_process_tree(
                            process,
                            limits.termination_grace_seconds,
                            windows_job=windows_job,
                        )
                    )
                finally:
                    raise
            except (OSError, RuntimeError) as exc:
                if windows_job is not None:
                    windows_job.close()
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await process.wait()
                return _result(
                    spec,
                    StageVerdict.INFRA_ERROR,
                    reason_code="windows_job_setup_error",
                    stderr=_clean_output(str(exc), redact_values),
                    duration_seconds=time.monotonic() - started,
                )
        else:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(cwd),
                env=dict(env),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
    except (OSError, ValueError) as exc:
        return _result(
            spec,
            StageVerdict.INFRA_ERROR,
            reason_code="spawn_error",
            stderr=_clean_output(str(exc), redact_values),
            duration_seconds=time.monotonic() - started,
        )

    assert process.stdout is not None and process.stderr is not None
    budget = _OutputBudget(limits.max_output_bytes)
    stdout_task = asyncio.create_task(_drain_stream(process.stdout, budget))
    stderr_task = asyncio.create_task(_drain_stream(process.stderr, budget))
    timed_out = False
    descendant_leak = False
    try:
        try:
            if windows_job is not None:
                await _wait_for_windows_process(windows_job, spec.timeout_seconds)
            else:
                await asyncio.wait_for(process.wait(), timeout=spec.timeout_seconds)
        except asyncio.TimeoutError:
            timed_out = True
            await _terminate_process_tree(
                process, limits.termination_grace_seconds, windows_job=windows_job
            )
        else:
            if windows_job is not None:
                windows_job.close()
                await asyncio.wait_for(
                    process.wait(), timeout=max(1.0, limits.termination_grace_seconds + 1.0)
                )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task),
                timeout=limits.drain_timeout_seconds,
            )
        except asyncio.TimeoutError:
            descendant_leak = True
            await _terminate_process_tree(process, 0, windows_job=windows_job)
            for task in (stdout_task, stderr_task):
                task.cancel()
            gathered = await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            stdout_bytes = gathered[0] if isinstance(gathered[0], bytes) else b""
            stderr_bytes = gathered[1] if isinstance(gathered[1], bytes) else b""
    except asyncio.CancelledError:
        try:
            await _await_cleanup(
                _cleanup_cancelled_process(
                    process,
                    (stdout_task, stderr_task),
                    limits.termination_grace_seconds,
                    windows_job=windows_job,
                )
            )
        finally:
            raise

    duration = time.monotonic() - started
    redactions = tuple(redact_values)
    stdout = _clean_output(
        stdout_bytes.decode("utf-8", errors="replace"),
        redactions,
        truncated=budget.truncated,
    )
    stderr = _clean_output(
        stderr_bytes.decode("utf-8", errors="replace"),
        redactions,
        truncated=budget.truncated,
    )
    stdout, stdout_cut = _cap_utf8(stdout, limits.max_output_bytes)
    remaining = max(0, limits.max_output_bytes - len(stdout.encode("utf-8")))
    stderr, stderr_cut = _cap_utf8(stderr, remaining)
    budget.truncated = budget.truncated or stdout_cut or stderr_cut
    if timed_out:
        return _result(
            spec,
            StageVerdict.TIMEOUT,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            truncated=budget.truncated,
            reason_code="timeout",
        )
    if descendant_leak:
        return _result(
            spec,
            StageVerdict.INFRA_ERROR,
            returncode=process.returncode,
            stdout=stdout,
            stderr=(
                stderr + "\nA descendant retained an output pipe after the command exited."
            ).strip(),
            duration_seconds=duration,
            truncated=budget.truncated,
            reason_code="descendant_process_leak",
        )
    if (
        os.name == "nt"
        and process.returncode == 255
        and stderr.startswith("VULNREPAIR_WINDOWS_WRAPPER_SPAWN_ERROR:")
    ):
        return _result(
            spec,
            StageVerdict.INFRA_ERROR,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr.removeprefix("VULNREPAIR_WINDOWS_WRAPPER_SPAWN_ERROR:").strip(),
            duration_seconds=duration,
            truncated=budget.truncated,
            reason_code="spawn_error",
        )
    if process.returncode != 0:
        return _result(
            spec,
            StageVerdict.FAIL,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            truncated=budget.truncated,
            reason_code="nonzero_exit",
        )
    return _result(
        spec,
        StageVerdict.PASS,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
        truncated=budget.truncated,
        reason_code="output_truncated" if budget.truncated else "ok",
    )


async def _drain_stream(stream: asyncio.StreamReader, budget: _OutputBudget) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            return b"".join(chunks)
        retained = budget.retain(chunk)
        if retained:
            chunks.append(retained)


async def _wait_for_windows_process(job: WindowsJob, timeout_seconds: float) -> None:
    """Wait for the wrapper handle, independent of descendant-held stdio pipes."""

    deadline = time.monotonic() + timeout_seconds
    while not job.process_exited():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError
        # Keep this above Windows' coarse monotonic-clock resolution.  A 10 ms
        # poll can otherwise make two concurrent timer loops repeatedly wake
        # each other early and spin without giving the child time to start.
        await asyncio.sleep(min(0.05, remaining))


async def _cleanup_cancelled_process(
    process: asyncio.subprocess.Process,
    stream_tasks: tuple[asyncio.Task[bytes], asyncio.Task[bytes]],
    grace_seconds: float,
    *,
    windows_job: WindowsJob | None = None,
) -> None:
    try:
        await _terminate_process_tree(process, grace_seconds, windows_job=windows_job)
    finally:
        for task in stream_tasks:
            task.cancel()
        await asyncio.gather(*stream_tasks, return_exceptions=True)


_CleanupResult = TypeVar("_CleanupResult")


async def _await_cleanup(awaitable: Awaitable[_CleanupResult]) -> _CleanupResult:
    """Finish cleanup before propagating any cancellation to the caller."""

    cleanup = asyncio.ensure_future(awaitable)
    cancelled = False
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            cancelled = True
    result = cleanup.result()
    if cancelled:
        raise asyncio.CancelledError
    return result


async def _terminate_process_tree(
    process: asyncio.subprocess.Process,
    grace_seconds: float,
    *,
    windows_job: WindowsJob | None = None,
) -> None:
    if windows_job is not None:
        windows_job.close()
        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=max(1.0, grace_seconds + 1.0))
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        return
    if process.returncode is not None:
        if os.name != "nt":
            _signal_process_group(process.pid, signal.SIGKILL)
        return
    if os.name == "nt":
        killed_tree = await _taskkill_windows_tree(process.pid, grace_seconds)
        if not killed_tree and process.returncode is None:
            process.kill()
    else:
        _signal_process_group(process.pid, signal.SIGTERM)
        if grace_seconds:
            try:
                await asyncio.wait_for(process.wait(), timeout=grace_seconds)
            except asyncio.TimeoutError:
                pass
        _signal_process_group(process.pid, signal.SIGKILL)
    if process.returncode is None:
        try:
            await asyncio.wait_for(process.wait(), timeout=max(1.0, grace_seconds + 1.0))
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()


async def _taskkill_windows_tree(pid: int, grace_seconds: float) -> bool:
    """Retry Windows' identity-aware tree kill without retaining stale child PIDs."""

    timeout = max(1.0, grace_seconds + 1.0)
    for attempt in range(3):
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(pid),
                "/T",
                "/F",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(killer.wait(), timeout=timeout)
        except (OSError, asyncio.TimeoutError):
            pass
        else:
            if killer.returncode == 0:
                return True
        if attempt < 2:
            await asyncio.sleep(0.05)
    return False


def _signal_process_group(pid: int, selected_signal: signal.Signals) -> None:
    try:
        os.killpg(pid, selected_signal)
    except ProcessLookupError:
        return
    except PermissionError:
        try:
            os.kill(pid, selected_signal)
        except ProcessLookupError:
            pass


def _validate_argv(argv: object) -> tuple[str, ...]:
    if not isinstance(argv, tuple) or not argv:
        raise ValueError("command argv must be a non-empty tuple; shell strings are forbidden")
    for argument in argv:
        if not isinstance(argument, str) or not argument or "\x00" in argument:
            raise ValueError("command argv contains an invalid argument")
        if any(character in argument for character in ("\r", "\n")):
            raise ValueError("command argv cannot contain line breaks")
    return argv


def _validate_relative_cwd(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("command cwd must be a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise ValueError("command cwd must stay within the workspace")
    return path


def _resolve_cwd(workspace: Path, value: str) -> Path:
    root = Path(workspace).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("workspace must be a directory")
    relative = _validate_relative_cwd(value)
    target = root.joinpath(*relative.parts).resolve(strict=True)
    if not target.is_dir() or Path(os.path.commonpath((str(root), str(target)))) != root:
        raise ValueError("command cwd escapes the workspace or is not a directory")
    return target


def _sanitized_environment(explicit: Mapping[str, str] | None) -> dict[str, str]:
    environment: dict[str, str] = {
        "LANG": "C.UTF-8" if os.name != "nt" else "C",
        "LC_ALL": "C.UTF-8" if os.name != "nt" else "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
    }
    for name in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    environment.update(_validated_explicit_environment(explicit))
    return environment


def _validated_explicit_environment(explicit: Mapping[str, str] | None) -> dict[str, str]:
    values: dict[str, str] = {}
    for name, value in (explicit or {}).items():
        if not isinstance(name, str) or not _ENV_NAME_RE.fullmatch(name):
            raise ValueError(f"invalid environment variable name: {name!r}")
        if _SENSITIVE_ENV_RE.search(name):
            raise ValueError(f"sensitive environment variables are forbidden: {name}")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError(f"invalid environment value for {name}")
        values[name] = value
    return values


def _redaction_values(
    supplied: Iterable[str],
    environment: Mapping[str, str] | None,
) -> tuple[str, ...]:
    values = {value for value in supplied if isinstance(value, str) and len(value) >= 4}
    values.update(value for value in (environment or {}).values() if len(value) >= 4)
    return tuple(sorted(values, key=len, reverse=True))


def _clean_output(value: str, redact_values: Iterable[str], *, truncated: bool = False) -> str:
    clean = _ANSI_ESCAPE_RE.sub("", value)
    clean = "".join(
        character for character in clean if character in "\n\r\t" or ord(character) >= 32
    )
    for secret in redact_values:
        clean = clean.replace(secret, "[REDACTED]")
        if truncated:
            for length in range(min(len(secret) - 1, len(clean)), 3, -1):
                prefix = secret[:length]
                if clean.endswith(prefix):
                    clean = clean[: -len(prefix)] + "[REDACTED]"
                    break
    return clean


def _cap_utf8(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _validate_immutable_image(image: str) -> None:
    if not isinstance(image, str) or not (
        _IMAGE_ID_RE.fullmatch(image) or _DIGEST_REFERENCE_RE.fullmatch(image)
    ):
        raise ValueError("Docker image must be a sha256 image ID or digest-pinned reference")


def _default_docker_user() -> str:
    """Use the owning host identity when it is safely non-root.

    Bind-mounted snapshots are owned by the coordinator.  Matching that numeric
    identity lets the non-root container write build artifacts without opening
    the snapshot to every host user.  A root coordinator falls back to an
    unprivileged container identity and ownership is staged immediately before
    mounting.
    """

    if os.name == "posix" and hasattr(os, "getuid") and os.getuid() != 0:
        return f"{os.getuid()}:{os.getgid()}"
    return "65532:65532"


def _prepare_workspace_for_container(root: Path, user: str) -> None:
    if os.name != "posix" or not hasattr(os, "getuid"):
        return
    uid_text, gid_text = user.split(":", 1)
    uid, gid = int(uid_text), int(gid_text)
    current_uid = os.getuid()
    if current_uid != 0:
        if uid != current_uid:
            raise ValueError("Docker user must match the non-root workspace owner")
        if not os.access(root, os.R_OK | os.W_OK | os.X_OK):
            raise ValueError("workspace is not writable by the configured Docker user")
        return

    paths = [root]
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in (*directories, *filenames):
            path = current_path / name
            if path.is_symlink():
                raise ValueError(f"workspace contains a symlink: {path.relative_to(root)}")
            if path != root and os.path.ismount(path):
                raise ValueError(f"workspace contains a nested mount: {path.relative_to(root)}")
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise ValueError(f"workspace contains a hard-linked file: {path.relative_to(root)}")
            paths.append(path)
    for path in paths:
        os.chown(path, uid, gid, follow_symlinks=False)


def _result(
    spec: CommandSpec,
    verdict: StageVerdict,
    *,
    returncode: int | None = None,
    stdout: str = "",
    stderr: str = "",
    duration_seconds: float = 0.0,
    truncated: bool = False,
    reason_code: str,
) -> CommandResult:
    return CommandResult(
        command=spec,
        verdict=verdict,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=max(0.0, duration_seconds),
        truncated=truncated,
        reason_code=reason_code,
    )


__all__ = [
    "DockerCommandRunner",
    "DockerLimits",
    "PodmanCommandRunner",
    "LocalCommandRunner",
    "RunnerLimits",
]
