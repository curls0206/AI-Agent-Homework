from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vulnrepair.contracts import CommandSpec, TrustedHarness, ValidationPlan  # noqa: E402
from vulnrepair.harness import (  # noqa: E402
    HarnessError,
    HarnessLimits,
    compute_harness_digest,
    verify_harness_binding,
)


class TrustedHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="harness-tests-")
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.harness = self.root / "harness"
        self.repo.mkdir()
        self.harness.mkdir()
        (self.repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.harness / "poc.py").write_text("print('ok')\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _trusted(self) -> TrustedHarness:
        return TrustedHarness(
            root=str(self.harness),
            digest_sha256=compute_harness_digest(self.harness),
        )

    def test_digest_is_deterministic_and_changes_with_content(self) -> None:
        first = compute_harness_digest(self.harness)
        second = compute_harness_digest(self.harness)
        self.assertEqual(first, second)

        (self.harness / "poc.py").write_text("print('changed')\n", encoding="utf-8")
        self.assertNotEqual(first, compute_harness_digest(self.harness))

    def test_digest_enforces_file_and_total_bounds(self) -> None:
        with self.assertRaisesRegex(HarnessError, "too large"):
            compute_harness_digest(
                self.harness,
                limits=HarnessLimits(max_files=1, max_total_bytes=4, max_file_bytes=4),
            )

    def test_host_command_must_reference_a_trusted_file(self) -> None:
        trusted = self._trusted()
        valid = ValidationPlan(
            harness=trusted,
            poc_command=CommandSpec(
                name="poc",
                argv=(sys.executable, str(self.harness / "poc.py")),
            ),
        )
        self.assertEqual(
            trusted.digest_sha256,
            verify_harness_binding(repo_path=self.repo, plan=valid),
        )

        invalid = ValidationPlan(
            harness=trusted,
            poc_command=CommandSpec(
                name="poc",
                argv=(sys.executable, str(self.repo / "app.py")),
            ),
        )
        with self.assertRaisesRegex(HarnessError, "must execute"):
            verify_harness_binding(repo_path=self.repo, plan=invalid)

    def test_container_command_and_mount_are_bound_to_same_digest(self) -> None:
        trusted = self._trusted()
        plan = ValidationPlan(
            harness=trusted,
            poc_command=CommandSpec(name="poc", argv=("python", "/harness/poc.py")),
        )
        self.assertEqual(
            trusted.digest_sha256,
            verify_harness_binding(
                repo_path=self.repo,
                plan=plan,
                runner_harness_dir=self.harness,
                runner_exposes_harness=True,
            ),
        )

        with self.assertRaisesRegex(HarnessError, "must execute"):
            verify_harness_binding(
                repo_path=self.repo,
                plan=ValidationPlan(
                    harness=trusted,
                    poc_command=CommandSpec(name="poc", argv=("python", "/workspace/poc.py")),
                ),
                runner_harness_dir=self.harness,
                runner_exposes_harness=True,
            )

    def test_unused_harness_argument_cannot_authorize_workspace_entrypoint(self) -> None:
        trusted = self._trusted()
        plan = ValidationPlan(
            harness=trusted,
            poc_command=CommandSpec(
                name="poc",
                argv=("python", "/workspace/candidate_probe.py", "/harness/poc.py"),
            ),
        )
        with self.assertRaisesRegex(HarnessError, "must execute"):
            verify_harness_binding(
                repo_path=self.repo,
                plan=plan,
                runner_harness_dir=self.harness,
                runner_exposes_harness=True,
            )

        candidate_probe = self.repo / "candidate_probe.py"
        candidate_probe.write_text("print('candidate controlled')\n", encoding="utf-8")
        host_plan = ValidationPlan(
            harness=trusted,
            poc_command=CommandSpec(
                name="poc",
                argv=(
                    sys.executable,
                    str(candidate_probe),
                    str(self.harness / "poc.py"),
                ),
            ),
        )
        with self.assertRaisesRegex(HarnessError, "must execute"):
            verify_harness_binding(repo_path=self.repo, plan=host_plan)

    def test_changed_or_overlapping_harness_is_rejected(self) -> None:
        trusted = self._trusted()
        plan = ValidationPlan(
            harness=trusted,
            poc_command=CommandSpec(
                name="poc",
                argv=(sys.executable, str(self.harness / "poc.py")),
            ),
        )
        (self.harness / "poc.py").write_text("print('tampered')\n", encoding="utf-8")
        with self.assertRaisesRegex(HarnessError, "do not match"):
            verify_harness_binding(repo_path=self.repo, plan=plan)

        in_repo = self.repo / "harness"
        in_repo.mkdir()
        (in_repo / "poc.py").write_text("print('untrusted')\n", encoding="utf-8")
        overlapping = ValidationPlan(
            harness=TrustedHarness(
                root=str(in_repo),
                digest_sha256=compute_harness_digest(in_repo),
            ),
            poc_command=CommandSpec(
                name="poc",
                argv=(sys.executable, str(in_repo / "poc.py")),
            ),
        )
        with self.assertRaisesRegex(HarnessError, "outside and disjoint"):
            verify_harness_binding(repo_path=self.repo, plan=overlapping)


if __name__ == "__main__":
    unittest.main()
