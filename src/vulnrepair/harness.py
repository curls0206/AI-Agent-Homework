"""Integrity checks for trusted, external validation harnesses.

Security evidence is only meaningful when the program producing it cannot be
modified by the candidate patch.  This module fingerprints a bounded external
directory and verifies that each security command executes a file from that
directory (or its read-only ``/harness`` Docker mount).
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from .contracts import CommandSpec, ValidationPlan


class HarnessError(ValueError):
    """A trusted harness failed an integrity or binding check."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class HarnessLimits:
    """Bounds that keep harness fingerprinting deterministic and inexpensive."""

    max_files: int = 256
    max_total_bytes: int = 16 * 1024 * 1024
    max_file_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_files <= 0 or self.max_total_bytes <= 0 or self.max_file_bytes <= 0:
            raise ValueError("harness limits must be positive")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("max_file_bytes cannot exceed max_total_bytes")


def compute_harness_digest(
    root: str | Path,
    *,
    limits: HarnessLimits | None = None,
) -> str:
    """Return a canonical SHA-256 digest for a trusted harness directory.

    Only regular files and directories are accepted.  Links, reparse points,
    devices, and files that change while being read are rejected.
    """

    selected_limits = limits or HarnessLimits()
    supplied = Path(root)
    try:
        supplied_stat = supplied.lstat()
        canonical = supplied.resolve(strict=True)
    except OSError as exc:
        raise HarnessError("harness_missing", f"trusted harness is unavailable: {exc}") from exc
    if _is_link_or_reparse(supplied_stat):
        raise HarnessError("harness_link_forbidden", "trusted harness root cannot be a link")
    if not stat.S_ISDIR(supplied_stat.st_mode) or not canonical.is_dir():
        raise HarnessError("harness_not_directory", "trusted harness root must be a directory")

    entries: list[tuple[str, Path, os.stat_result]] = []
    try:
        for entry in canonical.rglob("*"):
            entry_stat = entry.lstat()
            relative = entry.relative_to(canonical)
            relative_text = relative.as_posix()
            if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
                raise HarnessError(
                    "harness_path_invalid", "trusted harness contains an unsafe path"
                )
            if _is_link_or_reparse(entry_stat):
                raise HarnessError(
                    "harness_link_forbidden",
                    f"trusted harness contains a link: {relative_text}",
                )
            if stat.S_ISDIR(entry_stat.st_mode):
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise HarnessError(
                    "harness_nonregular_file",
                    f"trusted harness contains a non-regular file: {relative_text}",
                )
            entries.append((relative_text, entry, entry_stat))
    except HarnessError:
        raise
    except OSError as exc:
        raise HarnessError(
            "harness_scan_failed", f"trusted harness could not be scanned: {exc}"
        ) from exc

    entries.sort(key=lambda item: item[0].encode("utf-8"))
    if len(entries) > selected_limits.max_files:
        raise HarnessError("harness_file_limit", "trusted harness contains too many files")

    digest = hashlib.sha256()
    digest.update(b"vulnrepair-trusted-harness-v1\0")
    total_bytes = 0
    for relative_text, path, before in entries:
        if before.st_size > selected_limits.max_file_bytes:
            raise HarnessError(
                "harness_file_size_limit",
                f"trusted harness file is too large: {relative_text}",
            )
        total_bytes += before.st_size
        if total_bytes > selected_limits.max_total_bytes:
            raise HarnessError("harness_total_size_limit", "trusted harness is too large")
        content = _read_stable_regular_file(path, before, selected_limits.max_file_bytes)
        encoded_path = relative_text.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def verify_harness_binding(
    *,
    repo_path: str | Path,
    plan: ValidationPlan,
    runner_harness_dir: str | Path | None = None,
    runner_exposes_harness: bool = False,
) -> str | None:
    """Verify plan integrity and return the observed digest.

    ``runner_exposes_harness`` distinguishes a Docker-style runner whose
    ``harness_dir`` attribute exists (and therefore must match) from a local or
    test runner which executes host-absolute harness paths directly.
    """

    commands = tuple(_security_commands(plan))
    if not commands:
        return None
    trusted = plan.harness
    if trusted is None:  # Defensive even though ValidationPlan rejects this.
        raise HarnessError("trusted_harness_missing", "security commands require a trusted harness")

    try:
        repo = Path(repo_path).resolve(strict=True)
        root = Path(trusted.root).resolve(strict=True)
    except OSError as exc:
        raise HarnessError(
            "harness_path_unavailable", f"harness path validation failed: {exc}"
        ) from exc
    if not repo.is_dir():
        raise HarnessError("repository_not_directory", "repository path must be a directory")
    if _paths_overlap(repo, root):
        raise HarnessError(
            "harness_repository_overlap",
            "trusted harness must be outside and disjoint from the target repository",
        )

    observed = compute_harness_digest(root)
    if observed != trusted.digest_sha256:
        raise HarnessError(
            "harness_digest_mismatch",
            "trusted harness contents do not match the validation plan",
        )

    if runner_exposes_harness:
        if runner_harness_dir is None:
            raise HarnessError(
                "runner_harness_missing",
                "the selected sandbox runner has no trusted harness mount",
            )
        try:
            mounted = Path(runner_harness_dir).resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise HarnessError(
                "runner_harness_unavailable",
                f"the sandbox harness mount is unavailable: {exc}",
            ) from exc
        if mounted != root:
            raise HarnessError(
                "runner_harness_mismatch",
                "the sandbox harness mount differs from the validation plan",
            )
        for spec in commands:
            _verify_container_command(spec, root)
    else:
        for spec in commands:
            _verify_host_command(spec, root, repo)
    return observed


def _security_commands(plan: ValidationPlan) -> Iterable[CommandSpec]:
    if plan.poc_command is not None:
        yield plan.poc_command
    if plan.scanner_command is not None:
        yield plan.scanner_command


def _verify_host_command(spec: CommandSpec, root: Path, repo: Path) -> None:
    entrypoint_index: int | None = None
    for index, argument in enumerate(spec.argv):
        candidate = Path(argument)
        if not candidate.is_absolute():
            continue
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            entrypoint_index = index
            break
    _require_executed_harness_entrypoint(spec, entrypoint_index)
    if entrypoint_index == 1:
        runtime = Path(spec.argv[0])
        try:
            resolved_runtime = runtime.resolve(strict=True)
        except OSError as exc:
            raise HarnessError(
                "security_runtime_untrusted",
                f"security command {spec.name!r} must use an absolute trusted runtime: {exc}",
            ) from exc
        if not runtime.is_absolute() or not resolved_runtime.is_file():
            raise HarnessError(
                "security_runtime_untrusted",
                f"security command {spec.name!r} must use an absolute trusted runtime",
            )
        try:
            resolved_runtime.relative_to(repo)
        except ValueError:
            pass
        else:
            raise HarnessError(
                "security_runtime_untrusted",
                f"security command {spec.name!r} cannot execute a runtime from the target repository",
            )


def _verify_container_command(spec: CommandSpec, root: Path) -> None:
    mount = PurePosixPath("/harness")
    entrypoint_index: int | None = None
    for index, argument in enumerate(spec.argv):
        candidate = PurePosixPath(argument)
        if not candidate.is_absolute():
            continue
        try:
            relative = candidate.relative_to(mount)
        except ValueError:
            continue
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            continue
        host_target = root.joinpath(*relative.parts)
        try:
            resolved = host_target.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            entrypoint_index = index
            break
    _require_executed_harness_entrypoint(spec, entrypoint_index)
    if entrypoint_index == 1:
        runtime = PurePosixPath(spec.argv[0])
        if runtime.is_absolute():
            try:
                runtime.relative_to(PurePosixPath("/workspace"))
            except ValueError:
                pass
            else:
                raise HarnessError(
                    "security_runtime_untrusted",
                    f"security command {spec.name!r} cannot execute a runtime from /workspace",
                )
        elif len(runtime.parts) != 1 or runtime.parts[0] in {"", ".", ".."}:
            raise HarnessError(
                "security_runtime_untrusted",
                f"security command {spec.name!r} must use a runtime from the pinned image",
            )


def _require_executed_harness_entrypoint(
    spec: CommandSpec,
    entrypoint_index: int | None,
) -> None:
    if entrypoint_index not in {0, 1}:
        raise HarnessError(
            "security_command_not_bound_to_harness",
            f"security command {spec.name!r} must execute a trusted harness file directly "
            "or as the first argument to a trusted runtime",
        )


def _read_stable_regular_file(path: Path, before: os.stat_result, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
                raise HarnessError(
                    "harness_changed", f"trusted harness changed while reading: {path}"
                )
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) > limit:
                raise HarnessError(
                    "harness_file_size_limit", f"trusted harness file is too large: {path}"
                )
            after = os.fstat(descriptor)
            if not _same_file(opened, after) or after.st_size != len(content):
                raise HarnessError(
                    "harness_changed", f"trusted harness changed while reading: {path}"
                )
            return content
        finally:
            os.close(descriptor)
    except HarnessError:
        raise
    except OSError as exc:
        raise HarnessError(
            "harness_read_failed", f"trusted harness file could not be read: {exc}"
        ) from exc


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
    )


def _is_link_or_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(value.st_mode) or bool(attributes & reparse_flag)


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


__all__ = [
    "HarnessError",
    "HarnessLimits",
    "compute_harness_digest",
    "verify_harness_binding",
]
