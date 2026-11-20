"""Deterministic, bounded materialization of immutable Git snapshots."""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, BinaryIO, Iterator

from .contracts import SnapshotMetadata


class SnapshotError(RuntimeError):
    """Snapshot resolution, validation, extraction, or cleanup failed."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class SnapshotLimits:
    max_files: int = 20_000
    max_file_bytes: int = 32 * 1024 * 1024
    max_extracted_bytes: int = 256 * 1024 * 1024
    max_archive_bytes: int = 320 * 1024 * 1024
    max_tree_metadata_bytes: int = 32 * 1024 * 1024
    command_timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        numeric = (
            self.max_files,
            self.max_file_bytes,
            self.max_extracted_bytes,
            self.max_archive_bytes,
            self.max_tree_metadata_bytes,
        )
        if any(value <= 0 for value in numeric):
            raise ValueError("snapshot limits must be positive")
        if self.max_file_bytes > self.max_extracted_bytes:
            raise ValueError("max_file_bytes cannot exceed max_extracted_bytes")
        if not 0 < self.command_timeout_seconds <= 600:
            raise ValueError("command_timeout_seconds must be in (0, 600]")


@dataclass(frozen=True, slots=True)
class MaterializedSnapshot:
    root: Path
    metadata: SnapshotMetadata


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    path: str
    size: int
    executable: bool
    object_id: str


class SnapshotMaterializer:
    """Create a temporary tree exclusively from ``git archive <commit>``."""

    def __init__(
        self,
        *,
        limits: SnapshotLimits | None = None,
        workdir_parent: Path | None = None,
        git_executable: str | None = None,
    ) -> None:
        self.limits = limits or SnapshotLimits()
        self.workdir_parent = Path(workdir_parent).resolve() if workdir_parent else None
        discovered = git_executable or shutil.which("git")
        self.git_executable = str(Path(discovered).resolve()) if discovered else None

    @contextmanager
    def materialize(self, repo_path: Path, revision: str) -> Iterator[MaterializedSnapshot]:
        """Yield an exact commit snapshot and remove it on every exit path.

        Dirty and untracked working-tree content is intentionally ignored: all
        bytes originate from the resolved commit object.  Export attributes that
        would omit or rewrite committed files are rejected by tree/archive
        consistency checks.
        """

        repo = Path(repo_path).resolve(strict=True)
        if not repo.is_dir():
            raise SnapshotError("invalid_repository", f"repository is not a directory: {repo}")
        git = self.git_executable
        if not git:
            raise SnapshotError("git_missing", "git executable is not available")
        _validate_revision(revision)

        parent = self.workdir_parent
        if parent is not None:
            parent.mkdir(parents=True, exist_ok=True)
            parent = parent.resolve(strict=True)
        temporary_root = Path(tempfile.mkdtemp(prefix="vulnrepair-snapshot-", dir=parent))
        workspace = temporary_root / "workspace"
        workspace.mkdir(mode=0o700)
        body_error: BaseException | None = None
        try:
            self._ensure_repository(git, repo)
            commit = self._resolve_object(git, repo, f"{revision}^{{commit}}", "commit")
            tree_digest = self._resolve_object(git, repo, f"{commit}^{{tree}}", "tree")
            entries = self._read_tree(git, repo, commit)
            archive = self._run_git(
                git,
                repo,
                ("archive", "--format=tar", commit),
                output_limit=self.limits.max_archive_bytes,
            )
            archive_sha256 = hashlib.sha256(archive).hexdigest()
            self._extract_archive(archive, workspace, entries)
            metadata = SnapshotMetadata(
                commit=commit,
                tree_digest=tree_digest,
                archive_sha256=archive_sha256,
            )
            yield MaterializedSnapshot(root=workspace, metadata=metadata)
        except BaseException as exc:
            body_error = exc
            raise
        finally:
            try:
                _remove_tree(temporary_root)
            except Exception as cleanup_error:
                if body_error is not None:
                    body_error.add_note(f"snapshot cleanup failed: {cleanup_error}")
                else:
                    raise SnapshotError(
                        "cleanup_failed", f"snapshot cleanup failed: {cleanup_error}"
                    ) from cleanup_error

    def _ensure_repository(self, git: str, repo: Path) -> None:
        result = self._run_git(git, repo, ("rev-parse", "--git-dir"), output_limit=8_192)
        if not result.strip():
            raise SnapshotError("invalid_repository", f"not a Git repository: {repo}")

    def _resolve_object(self, git: str, repo: Path, revision: str, object_type: str) -> str:
        raw = self._run_git(
            git,
            repo,
            ("rev-parse", "--verify", revision),
            output_limit=8_192,
        )
        value = raw.decode("ascii", errors="strict").strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
            raise SnapshotError("invalid_object_id", f"Git returned an invalid {object_type} ID")
        return value

    def _read_tree(self, git: str, repo: Path, commit: str) -> tuple[_TreeEntry, ...]:
        raw = self._run_git(
            git,
            repo,
            ("ls-tree", "-r", "-z", "-l", "--full-tree", commit),
            output_limit=self.limits.max_tree_metadata_bytes,
        )
        entries: list[_TreeEntry] = []
        seen: set[str] = set()
        total_size = 0
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            fields = metadata.split()
            if not separator or len(fields) != 4:
                raise SnapshotError("invalid_tree", "could not parse git ls-tree output")
            mode, object_kind, raw_object_id, raw_size = fields
            try:
                path = raw_path.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise SnapshotError("unsafe_path", "non-UTF-8 Git paths are not supported") from exc
            _validate_archive_path(path)
            if path in seen:
                raise SnapshotError("duplicate_path", f"duplicate Git path: {path}")
            seen.add(path)
            if mode == b"120000":
                raise SnapshotError("symlink_entry", f"symlink entries are not allowed: {path}")
            if mode == b"160000" or object_kind == b"commit":
                raise SnapshotError("submodule_entry", f"submodule entries are not allowed: {path}")
            if object_kind != b"blob" or mode not in {b"100644", b"100755"}:
                raise SnapshotError("unsafe_tree_entry", f"unsupported tree entry {mode!r}: {path}")
            try:
                object_id = raw_object_id.decode("ascii", errors="strict")
            except UnicodeDecodeError as exc:
                raise SnapshotError("invalid_tree", f"invalid object ID for {path}") from exc
            if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id):
                raise SnapshotError("invalid_tree", f"invalid object ID for {path}")
            try:
                size = int(raw_size)
            except ValueError as exc:
                raise SnapshotError("invalid_tree", f"invalid blob size for {path}") from exc
            if size < 0 or size > self.limits.max_file_bytes:
                raise SnapshotError("file_too_large", f"file exceeds snapshot limit: {path}")
            total_size += size
            if total_size > self.limits.max_extracted_bytes:
                raise SnapshotError("snapshot_too_large", "tree exceeds max_extracted_bytes")
            entries.append(
                _TreeEntry(
                    path=path,
                    size=size,
                    executable=mode == b"100755",
                    object_id=object_id,
                )
            )
            if len(entries) > self.limits.max_files:
                raise SnapshotError("too_many_files", "tree exceeds max_files")
        return tuple(entries)

    def _extract_archive(
        self,
        archive: bytes,
        workspace: Path,
        entries: tuple[_TreeEntry, ...],
    ) -> None:
        expected = {entry.path: entry for entry in entries}
        extracted: set[str] = set()
        total_size = 0
        try:
            tar = tarfile.open(fileobj=io.BytesIO(archive), mode="r:")
        except tarfile.TarError as exc:
            raise SnapshotError(
                "invalid_archive", f"Git produced an invalid archive: {exc}"
            ) from exc
        with tar:
            for member in tar:
                name = member.name.rstrip("/")
                if not name:
                    continue
                _validate_archive_path(name)
                target = _safe_destination(workspace, name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o755)
                    continue
                if not member.isfile():
                    raise SnapshotError(
                        "unsafe_archive_entry", f"non-regular archive entry: {name}"
                    )
                entry = expected.get(name)
                if entry is None:
                    raise SnapshotError(
                        "tree_archive_mismatch", f"archive contains unexpected file: {name}"
                    )
                if name in extracted or member.size != entry.size:
                    raise SnapshotError(
                        "tree_archive_mismatch", f"archive disagrees with Git tree: {name}"
                    )
                if member.size > self.limits.max_file_bytes:
                    raise SnapshotError("file_too_large", f"archive file exceeds limit: {name}")
                total_size += member.size
                if total_size > self.limits.max_extracted_bytes:
                    raise SnapshotError("snapshot_too_large", "archive exceeds max_extracted_bytes")
                source = tar.extractfile(member)
                if source is None:
                    raise SnapshotError("invalid_archive", f"could not read archive member: {name}")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                _write_bounded_file(source, target, member.size, entry.object_id)
                target.chmod(0o755 if entry.executable else 0o644)
                extracted.add(name)
        missing = set(expected) - extracted
        if missing:
            sample = sorted(missing)[0]
            raise SnapshotError(
                "tree_archive_mismatch", f"archive omitted committed file: {sample}"
            )

    def _run_git(
        self,
        git: str,
        repo: Path,
        arguments: tuple[str, ...],
        *,
        output_limit: int,
    ) -> bytes:
        argv = (git, "-C", str(repo), *arguments)
        return _run_bounded_process(
            argv,
            env=_git_environment(),
            timeout=self.limits.command_timeout_seconds,
            stdout_limit=output_limit,
            stderr_limit=16_384,
        )


def _validate_revision(revision: str) -> None:
    if not isinstance(revision, str) or not revision or len(revision) > 256:
        raise SnapshotError(
            "invalid_revision", "revision must be non-empty and at most 256 characters"
        )
    if revision.startswith("-") or any(ord(character) < 32 for character in revision):
        raise SnapshotError("invalid_revision", "revision contains unsafe characters")


def _validate_archive_path(path: str) -> None:
    if not path or len(path.encode("utf-8")) > 4_096:
        raise SnapshotError("unsafe_path", "archive path is empty or too long")
    if path.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", path) or "\\" in path:
        raise SnapshotError("unsafe_path", f"absolute or non-portable archive path: {path!r}")
    parts = PurePosixPath(path).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise SnapshotError("unsafe_path", f"non-normal archive path: {path!r}")
    if any(ord(character) < 32 for character in path):
        raise SnapshotError("unsafe_path", f"control character in archive path: {path!r}")
    if any(part.endswith((" ", ".")) or ":" in part for part in parts):
        raise SnapshotError("unsafe_path", f"non-portable archive path: {path!r}")
    if any(part.casefold() == ".git" for part in parts):
        raise SnapshotError("vcs_metadata", f"archive contains VCS metadata: {path}")


def _safe_destination(root: Path, name: str) -> Path:
    # Hosted Windows runners may expose TEMP through a junction or 8.3 alias.
    # Compare canonical root and target forms so a benign alias is not treated
    # as an escape while genuine cross-root paths still fail closed.
    canonical_root = root.resolve(strict=True)
    target = canonical_root.joinpath(*PurePosixPath(name).parts)
    resolved = target.resolve(strict=False)
    try:
        common = Path(os.path.commonpath((str(canonical_root), str(resolved))))
    except ValueError as exc:
        raise SnapshotError("workspace_escape", f"archive path escapes workspace: {name}") from exc
    if common != canonical_root:
        raise SnapshotError("workspace_escape", f"archive path escapes workspace: {name}")
    return target


def _write_bounded_file(
    source: IO[bytes],
    destination: Path,
    expected_size: int,
    expected_object_id: str,
) -> None:
    written = 0
    if len(expected_object_id) == 40:
        digest = hashlib.sha1(usedforsecurity=False)
    elif len(expected_object_id) == 64:
        digest = hashlib.sha256()
    else:
        raise SnapshotError("invalid_tree", f"unsupported object ID: {destination.name}")
    digest.update(f"blob {expected_size}\0".encode("ascii"))
    with destination.open("xb") as output:
        while True:
            chunk = source.read(min(64 * 1024, expected_size - written + 1))
            if not chunk:
                break
            written += len(chunk)
            if written > expected_size:
                raise SnapshotError(
                    "tree_archive_mismatch",
                    f"archive member expanded beyond size: {destination.name}",
                )
            output.write(chunk)
            digest.update(chunk)
    if written != expected_size:
        raise SnapshotError(
            "tree_archive_mismatch", f"archive member was truncated: {destination.name}"
        )
    if digest.hexdigest() != expected_object_id:
        raise SnapshotError(
            "tree_archive_mismatch", f"archive content differs from Git blob: {destination.name}"
        )


def _run_bounded_process(
    argv: tuple[str, ...],
    *,
    env: dict[str, str],
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
) -> bytes:
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        raise SnapshotError("git_spawn_error", f"could not execute Git: {exc}") from exc
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    exceeded: list[str] = []

    def drain(stream: BinaryIO, destination: bytearray, limit: int, label: str) -> None:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            if len(destination) + len(chunk) > limit:
                remaining = max(0, limit - len(destination))
                destination.extend(chunk[:remaining])
                exceeded.append(label)
                try:
                    process.kill()
                except OSError:
                    pass
                return
            destination.extend(chunk)

    out_thread = threading.Thread(
        target=drain, args=(process.stdout, stdout, stdout_limit, "stdout"), daemon=True
    )
    err_thread = threading.Thread(
        target=drain, args=(process.stderr, stderr, stderr_limit, "stderr"), daemon=True
    )
    out_thread.start()
    err_thread.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise SnapshotError(
            "git_timeout", f"Git command timed out: {argv[3] if len(argv) > 3 else 'git'}"
        ) from exc
    finally:
        out_thread.join(timeout=5)
        err_thread.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    if exceeded:
        raise SnapshotError("git_output_limit", f"Git {exceeded[0]} exceeded its configured limit")
    if returncode != 0:
        detail = bytes(stderr).decode("utf-8", errors="replace").strip()
        raise SnapshotError("git_command_failed", detail or f"Git exited {returncode}")
    return bytes(stdout)


def _git_environment() -> dict[str, str]:
    env: dict[str, str] = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "LC_ALL": "C",
        "LANG": "C",
    }
    for name in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def _remove_tree(path: Path) -> None:
    def make_writable_and_retry(function: object, value: str, _error: object) -> None:
        target = Path(value)
        target.chmod(stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
        function(value)  # type: ignore[operator]

    shutil.rmtree(path, onerror=make_writable_and_retry)


__all__ = [
    "MaterializedSnapshot",
    "SnapshotError",
    "SnapshotLimits",
    "SnapshotMaterializer",
]
