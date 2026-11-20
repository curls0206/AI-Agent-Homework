"""Strict inspection and application of model-generated Git patches.

The parser intentionally supports a conservative subset of Git's unified-diff
format.  Ambiguous or uncommon constructs are rejected rather than delegated
to a more permissive patch implementation.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .contracts import PatchCandidate


class PatchPolicyError(ValueError):
    """A candidate patch violates the pre-execution policy."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class PatchApplyError(RuntimeError):
    """A policy-approved patch could not be applied exactly."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class PatchLimits:
    max_bytes: int = 256 * 1024
    max_files: int = 20
    max_changed_lines: int = 1_000
    apply_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.max_bytes <= 0 or self.max_files <= 0 or self.max_changed_lines <= 0:
            raise ValueError("patch limits must be positive")
        if not 0 < self.apply_timeout_seconds <= 300:
            raise ValueError("apply_timeout_seconds must be in (0, 300]")


@dataclass(frozen=True, slots=True)
class FilePatch:
    old_path: str | None
    new_path: str | None
    additions: int
    deletions: int

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or ""


@dataclass(frozen=True, slots=True)
class PatchInspection:
    digest_sha256: str
    file_patches: tuple[FilePatch, ...]
    additions: int
    deletions: int

    @property
    def changed_files(self) -> tuple[str, ...]:
        return tuple(item.path for item in self.file_patches)

    @property
    def changed_file_count(self) -> int:
        return len(self.file_patches)

    @property
    def changed_lines(self) -> int:
        return self.additions + self.deletions


@dataclass(frozen=True, slots=True)
class PatchPolicy:
    limits: PatchLimits = PatchLimits()
    allowed_path_prefixes: tuple[str, ...] = ()
    extra_forbidden_paths: tuple[str, ...] = ()
    git_executable: str | None = None

    def inspect(self, candidate: PatchCandidate, expected_task_id: str) -> PatchInspection:
        """Validate candidate identity and parse its diff without changing disk."""

        if not expected_task_id or candidate.task_id != expected_task_id:
            raise PatchPolicyError(
                "task_mismatch",
                f"candidate task {candidate.task_id!r} does not match {expected_task_id!r}",
            )
        return self.inspect_diff(candidate.diff)

    def inspect_diff(self, diff: str) -> PatchInspection:
        parser = _GitDiffParser(self)
        return parser.parse(diff)

    def apply(
        self,
        candidate: PatchCandidate,
        expected_task_id: str,
        workspace: Path,
    ) -> PatchInspection:
        """Inspect, check, and apply a candidate with Git and no fallback."""

        inspection = self.inspect(candidate, expected_task_id)
        root = Path(workspace).resolve(strict=True)
        if not root.is_dir():
            raise PatchApplyError("invalid_workspace", f"workspace is not a directory: {root}")
        for file_patch in inspection.file_patches:
            for relative in (file_patch.old_path, file_patch.new_path):
                if relative is not None:
                    _assert_workspace_path(root, relative)

        git = self.git_executable or shutil.which("git")
        if not git:
            raise PatchApplyError("git_missing", "git executable is not available")
        git_path = str(Path(git).resolve())
        payload = candidate.diff.encode("utf-8")
        common = [git_path, "apply", "--whitespace=error-all"]
        self._invoke_git(common + ["--check", "-"], root, payload, "patch_check_failed")
        self._invoke_git(common + ["-"], root, payload, "patch_apply_failed")
        return inspection

    def _invoke_git(
        self,
        argv: list[str],
        workspace: Path,
        payload: bytes,
        reason_code: str,
    ) -> None:
        env = _git_environment()
        try:
            completed = subprocess.run(
                argv,
                cwd=workspace,
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.limits.apply_timeout_seconds,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise PatchApplyError("patch_apply_timeout", "git apply timed out") from exc
        except OSError as exc:
            raise PatchApplyError("git_spawn_error", f"could not execute git: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr[:16_384].decode("utf-8", errors="replace").strip()
            raise PatchApplyError(reason_code, detail or f"git apply exited {completed.returncode}")


_HUNK_RE = re.compile(
    r"^@@ -(?:0|[1-9][0-9]*)(?:,([0-9]+))? \+(?:0|[1-9][0-9]*)(?:,([0-9]+))? @@(?: .*)?$"
)
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_MODE_RE = re.compile(r"^(?:new file mode|deleted file mode|old mode|new mode|index .+?) (\d{6})$")

_FORBIDDEN_SEGMENTS = frozenset(
    {
        ".git",
        ".github",
        ".circleci",
        ".azure",
        ".buildkite",
        ".mvn",
        "__snapshots__",
        "__tests__",
        "buildsrc",
        "ci",
        "gradle",
        "test",
        "tests",
        "poc",
        "pocs",
        "harness",
        "harnesses",
        "fixtures",
        "golden",
        "goldens",
        "scanner",
        "scanners",
        "snapshots",
        "spec",
        "specs",
        "test-data",
        "test-fixtures",
        "testdata",
        "test_fixtures",
    }
)
_TEST_BASENAME_RE = re.compile(
    r"(?:^|[._-])(?:test|tests|spec|specs)(?:[._-]|$)",
    re.IGNORECASE,
)
_FORBIDDEN_BASENAMES = frozenset(
    {
        ".gitlab-ci.yml",
        ".gitmodules",
        ".pre-commit-config.yaml",
        ".semgrep.yml",
        ".semgrep.yaml",
        "bandit.yaml",
        "bandit.yml",
        "build.gradle",
        "build.gradle.kts",
        "build.xml",
        "cargo.lock",
        "cargo.toml",
        "composer.json",
        "composer.lock",
        "compose.yaml",
        "compose.yml",
        "conftest.py",
        "docker-compose.yaml",
        "docker-compose.yml",
        "gradlew",
        "gradlew.bat",
        "gradle.properties",
        "go.mod",
        "go.sum",
        "jenkinsfile",
        "justfile",
        "makefile",
        "mvnw",
        "mvnw.cmd",
        "noxfile.py",
        "package-lock.json",
        "package.json",
        "pipfile",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pyproject.toml",
        "pytest.ini",
        "requirements.txt",
        "setup.cfg",
        "setup.py",
        "settings.gradle",
        "settings.gradle.kts",
        "sitecustomize.py",
        "tox.ini",
        "usercustomize.py",
        "uv.lock",
        "yarn.lock",
    }
)


@dataclass(slots=True)
class _MutableFilePatch:
    header_old: str
    header_new: str
    old_path: str | None = None
    new_path: str | None = None
    additions: int = 0
    deletions: int = 0
    saw_old_header: bool = False
    saw_new_header: bool = False
    saw_hunk: bool = False
    expected_old: int = 0
    expected_new: int = 0
    actual_old: int = 0
    actual_new: int = 0
    in_hunk: bool = False


class _GitDiffParser:
    def __init__(self, policy: PatchPolicy) -> None:
        self.policy = policy
        self.files: list[FilePatch] = []
        self.current: _MutableFilePatch | None = None
        self.seen_paths: set[str] = set()

    def parse(self, diff: str) -> PatchInspection:
        if not isinstance(diff, str):
            raise PatchPolicyError("diff_type", "diff must be text")
        try:
            payload = diff.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PatchPolicyError("diff_encoding", "diff must be valid UTF-8") from exc
        if not payload:
            raise PatchPolicyError("empty_diff", "diff is empty")
        if len(payload) > self.policy.limits.max_bytes:
            raise PatchPolicyError("patch_too_large", "diff exceeds max_bytes")
        if "\x00" in diff:
            raise PatchPolicyError("binary_patch", "NUL bytes are not allowed")

        for line_number, line in enumerate(diff.splitlines(), start=1):
            if line == "GIT binary patch" or line.startswith("Binary files "):
                raise PatchPolicyError("binary_patch", f"binary patch at line {line_number}")
            if line.startswith("Submodule "):
                raise PatchPolicyError("submodule_patch", f"submodule patch at line {line_number}")
            if line.startswith("diff --git "):
                self._finish_file(line_number)
                self.current = self._start_file(line, line_number)
                if len(self.files) + 1 > self.policy.limits.max_files:
                    raise PatchPolicyError("too_many_files", "diff exceeds max_files")
                continue
            if self.current is None:
                if line.strip():
                    raise PatchPolicyError(
                        "invalid_diff", f"content before first file at line {line_number}"
                    )
                continue
            self._consume_file_line(line, line_number)

        self._finish_file(len(diff.splitlines()) + 1)
        if not self.files:
            raise PatchPolicyError("empty_diff", "diff contains no file patches")
        additions = sum(item.additions for item in self.files)
        deletions = sum(item.deletions for item in self.files)
        return PatchInspection(
            digest_sha256=hashlib.sha256(payload).hexdigest(),
            file_patches=tuple(self.files),
            additions=additions,
            deletions=deletions,
        )

    def _start_file(self, line: str, line_number: int) -> _MutableFilePatch:
        payload = line[len("diff --git ") :]
        if payload.startswith('"') or "\\" in payload or payload.count(" b/") != 1:
            raise PatchPolicyError(
                "ambiguous_path", f"unsupported Git path quoting at line {line_number}"
            )
        old_token, new_suffix = payload.split(" b/", 1)
        if not old_token.startswith("a/") or not new_suffix:
            raise PatchPolicyError("invalid_diff", f"malformed file header at line {line_number}")
        old_path = old_token[2:]
        new_path = new_suffix
        _validate_path(old_path, self.policy)
        _validate_path(new_path, self.policy)
        if old_path != new_path:
            raise PatchPolicyError("rename_or_copy", "renames and copies are not allowed")
        return _MutableFilePatch(header_old=old_path, header_new=new_path)

    def _consume_file_line(self, line: str, line_number: int) -> None:
        assert self.current is not None
        current = self.current
        if line.startswith(
            ("rename from ", "rename to ", "copy from ", "copy to ", "similarity index ")
        ):
            raise PatchPolicyError("rename_or_copy", f"rename/copy metadata at line {line_number}")

        mode_match = _MODE_RE.match(line)
        if mode_match:
            mode = mode_match.group(1)
            if line.startswith(("old mode ", "new mode ")):
                raise PatchPolicyError("mode_change", f"mode change at line {line_number}")
            if mode in {"120000", "160000"}:
                reason = "symlink_patch" if mode == "120000" else "submodule_patch"
                raise PatchPolicyError(reason, f"unsafe Git mode {mode} at line {line_number}")
            if line.startswith("new file mode ") and mode != "100644":
                raise PatchPolicyError("mode_change", f"new file mode {mode} is not allowed")
            if mode not in {"100644", "100755"}:
                raise PatchPolicyError("mode_change", f"unsupported Git mode {mode}")
            return

        if line.startswith("--- "):
            if current.saw_old_header or current.in_hunk:
                raise PatchPolicyError("invalid_diff", f"duplicate old path at line {line_number}")
            value = line[4:]
            current.old_path = self._parse_marker_path(value, "a/", current.header_old, line_number)
            current.saw_old_header = True
            return
        if line.startswith("+++ "):
            if not current.saw_old_header or current.saw_new_header or current.in_hunk:
                raise PatchPolicyError("invalid_diff", f"misplaced new path at line {line_number}")
            value = line[4:]
            current.new_path = self._parse_marker_path(value, "b/", current.header_new, line_number)
            current.saw_new_header = True
            return
        if line.startswith("@@ "):
            if not current.saw_old_header or not current.saw_new_header:
                raise PatchPolicyError(
                    "invalid_diff", f"hunk precedes path headers at line {line_number}"
                )
            self._finish_hunk(line_number)
            match = _HUNK_RE.match(line)
            if not match:
                raise PatchPolicyError(
                    "invalid_hunk", f"malformed hunk header at line {line_number}"
                )
            current.expected_old = int(match.group(1) or "1")
            current.expected_new = int(match.group(2) or "1")
            current.actual_old = current.actual_new = 0
            current.in_hunk = current.saw_hunk = True
            return
        if current.in_hunk:
            if line.startswith("\\ No newline at end of file"):
                return
            if not line:
                raise PatchPolicyError(
                    "invalid_hunk", f"unprefixed empty hunk line at {line_number}"
                )
            prefix = line[0]
            if prefix == " ":
                current.actual_old += 1
                current.actual_new += 1
            elif prefix == "+":
                current.actual_new += 1
                current.additions += 1
            elif prefix == "-":
                current.actual_old += 1
                current.deletions += 1
            else:
                raise PatchPolicyError("invalid_hunk", f"invalid hunk line at {line_number}")
            if (
                current.additions
                + current.deletions
                + sum(item.additions + item.deletions for item in self.files)
                > self.policy.limits.max_changed_lines
            ):
                raise PatchPolicyError("too_many_changed_lines", "diff exceeds max_changed_lines")
            if (
                current.actual_old > current.expected_old
                or current.actual_new > current.expected_new
            ):
                raise PatchPolicyError("invalid_hunk", f"hunk line count exceeded at {line_number}")
            return
        if line.startswith("index "):
            if line.endswith(" 120000"):
                raise PatchPolicyError("symlink_patch", f"symlink index at line {line_number}")
            if line.endswith(" 160000"):
                raise PatchPolicyError("submodule_patch", f"submodule index at line {line_number}")
            return
        if line.strip():
            raise PatchPolicyError("invalid_diff", f"unexpected metadata at line {line_number}")

    def _parse_marker_path(
        self, value: str, prefix: str, expected: str, line_number: int
    ) -> str | None:
        if value == "/dev/null":
            return None
        if not value.startswith(prefix) or value[len(prefix) :] != expected:
            raise PatchPolicyError("path_mismatch", f"path marker mismatch at line {line_number}")
        return expected

    def _finish_hunk(self, line_number: int) -> None:
        if self.current is None or not self.current.in_hunk:
            return
        current = self.current
        if current.actual_old != current.expected_old or current.actual_new != current.expected_new:
            raise PatchPolicyError(
                "invalid_hunk", f"hunk line count mismatch before line {line_number}"
            )
        current.in_hunk = False

    def _finish_file(self, line_number: int) -> None:
        if self.current is None:
            return
        self._finish_hunk(line_number)
        current = self.current
        if not current.saw_old_header or not current.saw_new_header or not current.saw_hunk:
            raise PatchPolicyError(
                "invalid_diff", f"incomplete file patch before line {line_number}"
            )
        if current.old_path is None and current.new_path is None:
            raise PatchPolicyError("invalid_diff", "both file paths cannot be /dev/null")
        path = current.new_path or current.old_path
        assert path is not None
        if path in self.seen_paths:
            raise PatchPolicyError("duplicate_path", f"file appears more than once: {path}")
        self.seen_paths.add(path)
        self.files.append(
            FilePatch(
                old_path=current.old_path,
                new_path=current.new_path,
                additions=current.additions,
                deletions=current.deletions,
            )
        )
        self.current = None


def _validate_path(path: str, policy: PatchPolicy) -> None:
    if not path or path.startswith(("/", "\\")) or _WINDOWS_DRIVE_RE.match(path):
        raise PatchPolicyError("absolute_path", f"absolute path is not allowed: {path!r}")
    if "\\" in path or "//" in path or any(ord(char) < 32 for char in path):
        raise PatchPolicyError("unsafe_path", f"unsafe path characters: {path!r}")
    parts = PurePosixPath(path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise PatchPolicyError("path_traversal", f"non-normal path is not allowed: {path!r}")
    if any(part.endswith((" ", ".")) or ":" in part for part in parts):
        raise PatchPolicyError("unsafe_path", f"non-portable path is not allowed: {path!r}")
    lower_parts = tuple(part.casefold() for part in parts)
    if ".git" in lower_parts:
        raise PatchPolicyError("vcs_metadata", f"VCS metadata cannot be patched: {path}")
    if any(part in _FORBIDDEN_SEGMENTS for part in lower_parts):
        raise PatchPolicyError("validation_asset", f"validation asset cannot be patched: {path}")
    basename = lower_parts[-1]
    if (
        basename in _FORBIDDEN_BASENAMES
        or basename.startswith("requirements")
        and basename.endswith(".txt")
        or basename.startswith("dockerfile")
        or basename.endswith(".gemspec")
        or basename.endswith(".snap")
        or _TEST_BASENAME_RE.search(basename)
        or basename.startswith(("poc_", "scanner_"))
    ):
        raise PatchPolicyError(
            "validation_asset", f"build or validation asset cannot be patched: {path}"
        )

    for forbidden in policy.extra_forbidden_paths:
        normalized = forbidden.strip("/").casefold()
        lower_path = path.casefold()
        if normalized and (lower_path == normalized or lower_path.startswith(normalized + "/")):
            raise PatchPolicyError("validation_asset", f"policy-forbidden path: {path}")
    if policy.allowed_path_prefixes:
        allowed = tuple(item.strip("/").casefold() for item in policy.allowed_path_prefixes)
        lower_path = path.casefold()
        if not any(lower_path == item or lower_path.startswith(item + "/") for item in allowed):
            raise PatchPolicyError("path_not_allowed", f"path is outside allowed prefixes: {path}")


def _assert_workspace_path(root: Path, relative: str) -> None:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    resolved = candidate.resolve(strict=False)
    try:
        common = Path(os.path.commonpath((str(root), str(resolved))))
    except ValueError as exc:
        raise PatchApplyError("workspace_escape", f"path escapes workspace: {relative}") from exc
    if common != root:
        raise PatchApplyError("workspace_escape", f"path escapes workspace: {relative}")

    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current /= part
        if not current.exists():
            break
        metadata = current.lstat()
        is_reparse = bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
        if stat.S_ISLNK(metadata.st_mode) or is_reparse:
            raise PatchApplyError(
                "workspace_symlink", f"workspace path traverses a link: {relative}"
            )
    if candidate.exists() or candidate.is_symlink():
        metadata = candidate.lstat()
        is_reparse = bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
        if stat.S_ISLNK(metadata.st_mode) or is_reparse:
            raise PatchApplyError("workspace_symlink", f"target is a link: {relative}")


def _git_environment() -> dict[str, str]:
    env: dict[str, str] = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "LANG": "C",
    }
    for name in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


__all__ = [
    "FilePatch",
    "PatchApplyError",
    "PatchInspection",
    "PatchLimits",
    "PatchPolicy",
    "PatchPolicyError",
]
