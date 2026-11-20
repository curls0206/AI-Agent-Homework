from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from vulnrepair.contracts import PatchCandidate
from vulnrepair.patches import PatchApplyError, PatchLimits, PatchPolicy, PatchPolicyError

VALID_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-print('old')
+print('new')
"""


def candidate(diff: str = VALID_DIFF, *, task_id: str = "task-1") -> PatchCandidate:
    return PatchCandidate(task_id=task_id, diff=diff)


class PatchPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PatchPolicy()

    def assert_reason(self, reason: str, diff: str, *, policy: PatchPolicy | None = None) -> None:
        with self.assertRaises(PatchPolicyError) as raised:
            (policy or self.policy).inspect(candidate(diff), "task-1")
        self.assertEqual(raised.exception.reason_code, reason)

    def test_valid_diff_is_parsed_and_hashed(self) -> None:
        inspection = self.policy.inspect(candidate(), "task-1")
        self.assertEqual(inspection.changed_files, ("app.py",))
        self.assertEqual(inspection.additions, 1)
        self.assertEqual(inspection.deletions, 1)
        self.assertEqual(inspection.changed_lines, 2)
        self.assertEqual(len(inspection.digest_sha256), 64)

    def test_candidate_must_belong_to_task(self) -> None:
        with self.assertRaises(PatchPolicyError) as raised:
            self.policy.inspect(candidate(task_id="other-task"), "task-1")
        self.assertEqual(raised.exception.reason_code, "task_mismatch")

    def test_traversal_absolute_and_vcs_paths_are_rejected(self) -> None:
        for path, reason in (
            ("../escape.py", "path_traversal"),
            ("/etc/passwd", "absolute_path"),
            (".git/config", "vcs_metadata"),
            ("src//app.py", "unsafe_path"),
        ):
            with self.subTest(path=path):
                diff = VALID_DIFF.replace("app.py", path)
                self.assert_reason(reason, diff)

    def test_validation_and_build_assets_are_rejected(self) -> None:
        for path in (
            "tests/test_app.py",
            "poc/exploit.py",
            ".github/workflows/ci.yml",
            "pyproject.toml",
            "requirements-dev.txt",
            "Dockerfile",
            ".gitmodules",
            "src/conftest.py",
            "sitecustomize.py",
            "__tests__/app.test.js",
            "spec/app_spec.rb",
            "src/foo_test.go",
            "src/foo.test.ts",
            "src/foo_spec.rb",
            "src/foo.spec.ts",
            "src/component.snap",
            "fixtures/expected.json",
        ):
            with self.subTest(path=path):
                self.assert_reason("validation_asset", VALID_DIFF.replace("app.py", path))

    def test_binary_submodule_symlink_and_mode_changes_are_rejected(self) -> None:
        self.assert_reason(
            "binary_patch",
            "diff --git a/app.bin b/app.bin\nGIT binary patch\nliteral 0\n",
        )
        self.assert_reason(
            "submodule_patch",
            VALID_DIFF.replace("index 1111111..2222222 100644", "new file mode 160000"),
        )
        self.assert_reason(
            "symlink_patch",
            VALID_DIFF.replace("index 1111111..2222222 100644", "new file mode 120000"),
        )
        self.assert_reason(
            "mode_change",
            VALID_DIFF.replace(
                "index 1111111..2222222 100644",
                "old mode 100644\nnew mode 100755",
            ),
        )

    def test_rename_and_quoted_paths_are_rejected(self) -> None:
        renamed = VALID_DIFF.replace(
            "diff --git a/app.py b/app.py",
            "diff --git a/app.py b/new.py",
        ).replace("+++ b/app.py", "+++ b/new.py")
        self.assert_reason("rename_or_copy", renamed)
        quoted = VALID_DIFF.replace(
            "diff --git a/app.py b/app.py",
            'diff --git "a/app.py" "b/app.py"',
        )
        self.assert_reason("ambiguous_path", quoted)

    def test_size_file_and_changed_line_limits_are_enforced(self) -> None:
        self.assert_reason(
            "patch_too_large",
            VALID_DIFF,
            policy=PatchPolicy(limits=PatchLimits(max_bytes=32)),
        )
        second = (
            VALID_DIFF.replace("app.py", "second.py")
            .replace("old", "before")
            .replace("new", "after")
        )
        self.assert_reason(
            "too_many_files",
            VALID_DIFF + second,
            policy=PatchPolicy(limits=PatchLimits(max_files=1)),
        )
        self.assert_reason(
            "too_many_changed_lines",
            VALID_DIFF,
            policy=PatchPolicy(limits=PatchLimits(max_changed_lines=1)),
        )

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_apply_uses_strict_git_path_and_changes_only_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app.py"
            target.write_bytes(b"print('old')\n")
            inspection = self.policy.apply(candidate(), "task-1", root)
            self.assertEqual(target.read_bytes(), b"print('new')\n")
            self.assertEqual(inspection.changed_files, ("app.py",))

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_failed_check_never_mutates_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app.py"
            target.write_text("different content\n", encoding="utf-8")
            before = target.read_bytes()
            with self.assertRaises(PatchApplyError) as raised:
                self.policy.apply(candidate(), "task-1", root)
            self.assertEqual(raised.exception.reason_code, "patch_check_failed")
            self.assertEqual(target.read_bytes(), before)
            self.assertFalse((root / "app.py.rej").exists())
            self.assertFalse((root / "app.py.orig").exists())


if __name__ == "__main__":
    unittest.main()
