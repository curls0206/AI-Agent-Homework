from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from vulnrepair.snapshot import (
    SnapshotError,
    SnapshotLimits,
    SnapshotMaterializer,
    _safe_destination,
)

GIT = shutil.which("git")


@unittest.skipUnless(GIT, "git is required")
class SnapshotMaterializerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Snapshot Test")
        self.git("config", "user.email", "snapshot@example.invalid")
        (self.repo / "app.py").write_text("print('committed')\n", encoding="utf-8")
        self.git("add", "app.py")
        self.git("commit", "-qm", "initial")

    def test_workspace_root_alias_is_canonicalized_before_escape_check(self) -> None:
        actual = self.root / "actual-workspace"
        alias = self.root / "workspace-alias"
        actual.mkdir()
        if os.name == "nt":
            linked = subprocess.run(
                ("cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(actual)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if linked.returncode != 0:
                self.skipTest("directory junctions are unavailable")
        else:
            try:
                alias.symlink_to(actual, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory links are unavailable: {exc}")

        destination = _safe_destination(alias, "nested/app.py")

        self.assertEqual(actual.resolve() / "nested" / "app.py", destination)

    def git(self, *arguments: str, input_bytes: bytes | None = None) -> str:
        completed = subprocess.run(
            (GIT, "-C", str(self.repo), *arguments),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
        return completed.stdout.decode("utf-8", errors="strict").strip()

    def test_exact_commit_ignores_dirty_and_untracked_files_and_cleans_up(self) -> None:
        commit = self.git("rev-parse", "HEAD")
        tree = self.git("rev-parse", "HEAD^{tree}")
        (self.repo / "app.py").write_text("print('dirty')\n", encoding="utf-8")
        (self.repo / "untracked-secret.txt").write_text("do not copy", encoding="utf-8")
        parent = self.root / "snapshots"
        materializer = SnapshotMaterializer(workdir_parent=parent)
        snapshot_root: Path | None = None
        with materializer.materialize(self.repo, "HEAD") as snapshot:
            snapshot_root = snapshot.root
            self.assertEqual(snapshot.metadata.commit, commit)
            self.assertEqual(snapshot.metadata.tree_digest, tree)
            self.assertEqual(len(snapshot.metadata.archive_sha256), 64)
            self.assertEqual(
                (snapshot.root / "app.py").read_text(encoding="utf-8"), "print('committed')\n"
            )
            self.assertFalse((snapshot.root / "untracked-secret.txt").exists())
            self.assertFalse((snapshot.root / ".git").exists())
        assert snapshot_root is not None
        self.assertFalse(snapshot_root.parent.exists())
        self.assertEqual((self.repo / "app.py").read_text(encoding="utf-8"), "print('dirty')\n")

    def test_invalid_revision_is_rejected_and_temp_root_is_cleaned(self) -> None:
        parent = self.root / "snapshots"
        materializer = SnapshotMaterializer(workdir_parent=parent)
        with self.assertRaises(SnapshotError):
            with materializer.materialize(self.repo, "missing-ref"):
                pass
        self.assertEqual(list(parent.iterdir()), [])
        with self.assertRaises(SnapshotError) as raised:
            with materializer.materialize(self.repo, "--upload-pack=evil"):
                pass
        self.assertEqual(raised.exception.reason_code, "invalid_revision")

    def test_file_and_total_size_limits_are_enforced(self) -> None:
        materializer = SnapshotMaterializer(
            limits=SnapshotLimits(max_file_bytes=4, max_extracted_bytes=8)
        )
        with self.assertRaises(SnapshotError) as raised:
            with materializer.materialize(self.repo, "HEAD"):
                pass
        self.assertEqual(raised.exception.reason_code, "file_too_large")

    def test_symlink_tree_entry_is_rejected_without_creating_host_symlink(self) -> None:
        blob = self.git("hash-object", "-w", "--stdin", input_bytes=b"outside")
        self.git("update-index", "--add", "--cacheinfo", f"120000,{blob},link")
        self.git("commit", "-qm", "add synthetic symlink")
        with self.assertRaises(SnapshotError) as raised:
            with SnapshotMaterializer().materialize(self.repo, "HEAD"):
                pass
        self.assertEqual(raised.exception.reason_code, "symlink_entry")

    def test_submodule_tree_entry_is_rejected(self) -> None:
        commit = self.git("rev-parse", "HEAD")
        self.git("update-index", "--add", "--cacheinfo", f"160000,{commit},vendor")
        self.git("commit", "-qm", "add synthetic gitlink")
        with self.assertRaises(SnapshotError) as raised:
            with SnapshotMaterializer().materialize(self.repo, "HEAD"):
                pass
        self.assertEqual(raised.exception.reason_code, "submodule_entry")

    def test_export_attributes_cannot_hide_committed_files(self) -> None:
        (self.repo / ".gitattributes").write_text("secret.txt export-ignore\n", encoding="utf-8")
        (self.repo / "secret.txt").write_text("committed secret\n", encoding="utf-8")
        self.git("add", ".gitattributes", "secret.txt")
        self.git("commit", "-qm", "add export-ignore")
        with self.assertRaises(SnapshotError) as raised:
            with SnapshotMaterializer().materialize(self.repo, "HEAD"):
                pass
        self.assertEqual(raised.exception.reason_code, "tree_archive_mismatch")

    def test_archive_content_must_match_git_blob_not_only_size(self) -> None:
        test_case = self

        class TamperingMaterializer(SnapshotMaterializer):
            def _run_git(
                self, git: str, repo: Path, arguments: tuple[str, ...], *, output_limit: int
            ) -> bytes:
                value = super()._run_git(git, repo, arguments, output_limit=output_limit)
                if arguments and arguments[0] == "archive":
                    source_buffer = io.BytesIO(value)
                    output_buffer = io.BytesIO()
                    with tarfile.open(fileobj=source_buffer, mode="r:") as source:
                        with tarfile.open(fileobj=output_buffer, mode="w:") as output:
                            for member in source:
                                payload = (
                                    source.extractfile(member).read() if member.isfile() else None
                                )
                                if member.name == "app.py":
                                    replacement = b"print('corrupted')\n"
                                    test_case.assertEqual(len(replacement), member.size)
                                    payload = replacement
                                output.addfile(
                                    member, io.BytesIO(payload) if payload is not None else None
                                )
                    return output_buffer.getvalue()
                return value

        with self.assertRaises(SnapshotError) as raised:
            with TamperingMaterializer().materialize(self.repo, "HEAD"):
                pass
        self.assertEqual(raised.exception.reason_code, "tree_archive_mismatch")

    def test_git_replace_refs_cannot_substitute_requested_commit(self) -> None:
        original = self.git("rev-parse", "HEAD")
        (self.repo / "app.py").write_text("print('replacement')\n", encoding="utf-8")
        self.git("add", "app.py")
        self.git("commit", "-qm", "replacement content")
        replacement = self.git("rev-parse", "HEAD")
        self.git("replace", original, replacement)

        with SnapshotMaterializer().materialize(self.repo, original) as snapshot:
            self.assertEqual(original, snapshot.metadata.commit)
            self.assertEqual(
                "print('committed')\n",
                (snapshot.root / "app.py").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
