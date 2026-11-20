from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vulnrepair.contracts import (  # noqa: E402
    CommandResult,
    CommandSpec,
    OverallVerdict,
    PatchCandidate,
    SecurityOutcome,
    StageVerdict,
    TrustedHarness,
    ValidationPlan,
    VulnTask,
)
from vulnrepair.harness import compute_harness_digest  # noqa: E402
from vulnrepair.oracle import VerificationOracle  # noqa: E402

TARGET_FINDING = "xss:app.py:MODE"
VULNERABLE_SOURCE = 'MODE = "vulnerable"\n'
PATCHED_SOURCE = 'MODE = "patched"\n'

CORRECT_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-MODE = "vulnerable"
+MODE = "patched"
"""

NOOP_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1,2 @@
 MODE = "vulnerable"
+COMMENT = "no security change"
"""

NON_APPLYING_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-MODE = "not-the-base-content"
+MODE = "patched"
"""

REGRESSION_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-MODE = "vulnerable"
+MODE = "BROKEN"
"""


def _command(name: str, *, required: bool = True) -> CommandSpec:
    return CommandSpec(name=name, argv=(f"fake-{name}",), required=required)


def _candidate(task_id: str, diff: str) -> PatchCandidate:
    return PatchCandidate(task_id=task_id, diff=diff, generated_by="test")


class ScriptedRunner:
    """Deterministic runner that derives evidence from the materialized tree."""

    def __init__(self) -> None:
        self.behavior: dict[str, str] = {}
        self.mutate_build_workspace = False
        self.workspaces: dict[str, list[Path]] = {}

    async def run(self, spec: CommandSpec, workspace: Path) -> CommandResult:
        workspace = workspace.resolve()
        self.workspaces.setdefault(spec.name, []).append(workspace)
        behavior = self.behavior.get(spec.name, "auto")
        if behavior == "missing":
            raise FileNotFoundError(spec.argv[0])
        if behavior == "timeout":
            return self._result(
                spec,
                verdict=StageVerdict.TIMEOUT,
                returncode=None,
                reason_code="command_timeout",
            )
        if behavior == "nonzero":
            return self._result(
                spec,
                verdict=StageVerdict.FAIL,
                returncode=7,
                stderr="harness exited nonzero",
                reason_code="nonzero_exit",
            )
        if behavior == "malformed":
            return self._result(spec, stdout="{not-json")
        if behavior == "unhealthy":
            return self._result(
                spec,
                stdout=json.dumps(
                    {
                        "schema_version": "1.0",
                        "harness_ok": False,
                        "outcome": "blocked",
                    }
                ),
            )

        source = (workspace / "app.py").read_text(encoding="utf-8")
        if spec.name == "build":
            if self.mutate_build_workspace:
                (workspace / "app.py").write_text(PATCHED_SOURCE, encoding="utf-8")
            if "BROKEN" in source:
                return self._result(
                    spec,
                    verdict=StageVerdict.FAIL,
                    returncode=1,
                    reason_code="build_failed",
                )
            return self._result(spec)
        if spec.name == "test":
            if "BROKEN" in source:
                return self._result(
                    spec,
                    verdict=StageVerdict.FAIL,
                    returncode=1,
                    reason_code="tests_failed",
                )
            return self._result(spec)
        if spec.name == "poc":
            if behavior == "force_blocked":
                outcome = "blocked"
            elif behavior == "not_available":
                outcome = "not_available"
            else:
                outcome = "blocked" if 'MODE = "patched"' in source else "vulnerable"
            return self._result(
                spec,
                stdout=json.dumps(
                    {
                        "schema_version": "1.0",
                        "harness_ok": True,
                        "outcome": outcome,
                    }
                ),
            )
        if spec.name == "scanner":
            findings = [] if 'MODE = "patched"' in source else [{"fingerprint": TARGET_FINDING}]
            return self._result(
                spec,
                stdout=json.dumps(
                    {
                        "schema_version": "1.0",
                        "harness_ok": True,
                        "findings": findings,
                    }
                ),
            )
        raise AssertionError(f"unexpected fake command: {spec.name}")

    @staticmethod
    def _result(
        spec: CommandSpec,
        *,
        verdict: StageVerdict = StageVerdict.PASS,
        returncode: int | None = 0,
        stdout: str = "",
        stderr: str = "",
        reason_code: str = "command_passed",
    ) -> CommandResult:
        return CommandResult(
            command=spec,
            verdict=verdict,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=0.001,
            reason_code=reason_code,
        )


class VerificationOracleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="oracle-tests-")
        self.repo = Path(self.temporary.name) / "repo"
        self.harness = Path(self.temporary.name) / "harness"
        self.repo.mkdir()
        self.harness.mkdir()
        (self.repo / "app.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
        (self.harness / "poc.py").write_text("# trusted PoC fixture\n", encoding="utf-8")
        (self.harness / "scanner.py").write_text("# trusted scanner fixture\n", encoding="utf-8")
        self._git("init", "-q")
        self._git("config", "user.email", "oracle@example.invalid")
        self._git("config", "user.name", "Oracle Tests")
        self._git("add", "app.py")
        self._git("commit", "-q", "-m", "vulnerable base")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        self.task = VulnTask(
            task_id="task-1",
            cve_id="CVE-2099-0001",
            cwe_id="CWE-79",
            description="fixture XSS",
            repo_path=str(self.repo),
            language="python",
            affected_versions="1.0",
            base_ref=self.commit,
        )
        self.runner = ScriptedRunner()
        self.oracle = VerificationOracle(self.runner)
        self.trusted_harness = TrustedHarness(
            root=str(self.harness),
            digest_sha256=compute_harness_digest(self.harness),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ("git", "-C", str(self.repo), *args),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def _plan(self, *, poc: bool = True, scanner: bool = True) -> ValidationPlan:
        return ValidationPlan(
            harness=self.trusted_harness if poc or scanner else None,
            build_commands=(_command("build"),),
            test_commands=(_command("test"),),
            poc_command=(
                CommandSpec(
                    name="poc",
                    argv=(sys.executable, str(self.harness / "poc.py")),
                )
                if poc
                else None
            ),
            scanner_command=(
                CommandSpec(
                    name="scanner",
                    argv=(sys.executable, str(self.harness / "scanner.py")),
                )
                if scanner
                else None
            ),
            target_finding=TARGET_FINDING if scanner else None,
        )

    async def test_baseline_uses_exact_commit_and_structured_evidence(self) -> None:
        (self.repo / "app.py").write_text(PATCHED_SOURCE, encoding="utf-8")

        baseline = await self.oracle.prepare_baseline(self.task, self._plan())

        self.assertTrue(baseline.usable)
        self.assertEqual(self.commit, baseline.snapshot.commit)
        outcomes = {item.stage: item.security_outcome for item in baseline.stages}
        self.assertEqual(SecurityOutcome.VULNERABLE, outcomes["baseline.poc"])
        self.assertEqual(SecurityOutcome.FINDING_PRESENT, outcomes["baseline.scanner"])
        self.assertEqual(
            PATCHED_SOURCE,
            (self.repo / "app.py").read_text(encoding="utf-8"),
            "Oracle must never mutate or reset the source worktree",
        )

    async def test_correct_patch_is_verified_with_poc_and_scanner_delta(self) -> None:
        plan = self._plan()
        baseline = await self.oracle.prepare_baseline(self.task, plan)

        result = await self.oracle.validate(
            _candidate(self.task.task_id, CORRECT_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.VERIFIED_FIX, result.overall)
        outcomes = {item.stage: item.security_outcome for item in result.stages}
        self.assertEqual(SecurityOutcome.BLOCKED, outcomes["candidate.poc"])
        self.assertEqual(SecurityOutcome.CLEAN, outcomes["candidate.scanner"])

    async def test_build_workspace_cannot_tamper_with_security_evidence(self) -> None:
        self.runner.mutate_build_workspace = True
        plan = self._plan(poc=True, scanner=False)
        baseline = await self.oracle.prepare_baseline(self.task, plan)
        self.assertTrue(baseline.usable)

        result = await self.oracle.validate(
            _candidate(self.task.task_id, NOOP_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.REJECTED, result.overall)
        self.assertEqual(
            SecurityOutcome.VULNERABLE,
            next(item for item in result.stages if item.stage == "candidate.poc").security_outcome,
        )
        self.assertNotEqual(
            self.runner.workspaces["build"][-1],
            self.runner.workspaces["poc"][-1],
        )

    async def test_no_security_signal_is_inconclusive(self) -> None:
        plan = self._plan(poc=False, scanner=False)
        baseline = await self.oracle.prepare_baseline(self.task, plan)
        self.assertFalse(baseline.usable)

        result = await self.oracle.validate(
            _candidate(self.task.task_id, CORRECT_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.INCONCLUSIVE, result.overall)
        self.assertNotIn("candidate.patch.build", {item.stage for item in result.stages})

    async def test_baseline_cannot_be_reused_with_a_weaker_plan(self) -> None:
        baseline_plan = self._plan(poc=True, scanner=False)
        baseline = await self.oracle.prepare_baseline(self.task, baseline_plan)
        weaker_plan = ValidationPlan(
            harness=self.trusted_harness,
            poc_command=CommandSpec(
                name="poc",
                argv=(sys.executable, str(self.harness / "poc.py")),
            ),
        )

        result = await self.oracle.validate(
            _candidate(self.task.task_id, CORRECT_DIFF),
            self.task,
            weaker_plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.INFRA_ERROR, result.overall)
        self.assertEqual("baseline_plan_mismatch", result.stages[-1].reason_code)
        self.assertNotIn("candidate.patch.build", {item.stage for item in result.stages})

    async def test_in_repository_probe_cannot_be_trusted_security_evidence(self) -> None:
        in_repo_probe = self.repo / "probe.py"
        in_repo_probe.write_text("print('candidate-controlled')\n", encoding="utf-8")
        plan = ValidationPlan(
            harness=TrustedHarness(
                root=str(self.repo),
                digest_sha256=compute_harness_digest(self.repo),
            ),
            poc_command=CommandSpec(
                name="poc",
                argv=(sys.executable, str(in_repo_probe)),
            ),
        )

        baseline = await self.oracle.prepare_baseline(self.task, plan)

        self.assertFalse(baseline.usable)
        self.assertEqual(StageVerdict.INFRA_ERROR, baseline.stages[0].verdict)
        self.assertEqual("harness_repository_overlap", baseline.stages[0].reason_code)
        self.assertFalse(self.runner.workspaces)

    async def test_harness_mutation_after_baseline_blocks_candidate(self) -> None:
        plan = self._plan(poc=True, scanner=False)
        baseline = await self.oracle.prepare_baseline(self.task, plan)
        self.assertTrue(baseline.usable)
        (self.harness / "poc.py").write_text("# modified after baseline\n", encoding="utf-8")

        result = await self.oracle.validate(
            _candidate(self.task.task_id, CORRECT_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.INFRA_ERROR, result.overall)
        harness = next(item for item in result.stages if item.stage == "candidate.harness.initial")
        self.assertEqual("harness_digest_mismatch", harness.reason_code)
        self.assertNotIn("candidate.patch.build", {item.stage for item in result.stages})

    async def test_surviving_exploit_and_scanner_finding_are_rejected(self) -> None:
        plan = self._plan()
        baseline = await self.oracle.prepare_baseline(self.task, plan)

        result = await self.oracle.validate(
            _candidate(self.task.task_id, NOOP_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.REJECTED, result.overall)

    async def test_security_harness_failures_are_infrastructure_errors(self) -> None:
        plan = self._plan(poc=True, scanner=False)
        baseline = await self.oracle.prepare_baseline(self.task, plan)
        candidate = _candidate(self.task.task_id, CORRECT_DIFF)

        for behavior in ("malformed", "nonzero", "timeout", "missing", "unhealthy"):
            with self.subTest(behavior=behavior):
                self.runner.behavior["poc"] = behavior
                result = await self.oracle.validate(candidate, self.task, plan, baseline)
                self.assertEqual(OverallVerdict.INFRA_ERROR, result.overall)
                poc = next(item for item in result.stages if item.stage == "candidate.poc")
                self.assertIn(
                    poc.verdict,
                    (StageVerdict.INFRA_ERROR, StageVerdict.TIMEOUT),
                )
                self.assertEqual(SecurityOutcome.HARNESS_ERROR, poc.security_outcome)
        self.runner.behavior.pop("poc", None)

    async def test_scanner_harness_failures_are_infrastructure_errors(self) -> None:
        plan = self._plan(poc=False, scanner=True)
        baseline = await self.oracle.prepare_baseline(self.task, plan)
        candidate = _candidate(self.task.task_id, CORRECT_DIFF)

        for behavior in ("malformed", "nonzero", "timeout", "missing", "unhealthy"):
            with self.subTest(behavior=behavior):
                self.runner.behavior["scanner"] = behavior
                result = await self.oracle.validate(candidate, self.task, plan, baseline)
                self.assertEqual(OverallVerdict.INFRA_ERROR, result.overall)
                scanner = next(item for item in result.stages if item.stage == "candidate.scanner")
                self.assertIn(
                    scanner.verdict,
                    (StageVerdict.INFRA_ERROR, StageVerdict.TIMEOUT),
                )
                self.assertEqual(
                    SecurityOutcome.HARNESS_ERROR,
                    scanner.security_outcome,
                )
        self.runner.behavior.pop("scanner", None)

    async def test_required_patched_evidence_not_available_is_inconclusive(self) -> None:
        plan = self._plan(poc=True, scanner=False)
        baseline = await self.oracle.prepare_baseline(self.task, plan)
        self.runner.behavior["poc"] = "not_available"

        result = await self.oracle.validate(
            _candidate(self.task.task_id, CORRECT_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.INCONCLUSIVE, result.overall)
        poc = next(item for item in result.stages if item.stage == "candidate.poc")
        self.assertEqual(StageVerdict.SKIPPED, poc.verdict)
        self.assertEqual(SecurityOutcome.NOT_AVAILABLE, poc.security_outcome)

    async def test_baseline_harness_infrastructure_error_is_preserved(self) -> None:
        self.runner.behavior["poc"] = "nonzero"
        plan = self._plan(poc=True, scanner=False)

        baseline = await self.oracle.prepare_baseline(self.task, plan)
        result = await self.oracle.validate(
            _candidate(self.task.task_id, CORRECT_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertFalse(baseline.usable)
        self.assertEqual(OverallVerdict.INFRA_ERROR, result.overall)
        self.assertFalse(any(stage.stage.startswith("candidate.patch") for stage in result.stages))

    async def test_baseline_not_vulnerable_is_unusable_and_inconclusive(self) -> None:
        self.runner.behavior["poc"] = "force_blocked"
        plan = self._plan(poc=True, scanner=False)

        baseline = await self.oracle.prepare_baseline(self.task, plan)
        result = await self.oracle.validate(
            _candidate(self.task.task_id, CORRECT_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertFalse(baseline.usable)
        self.assertEqual(OverallVerdict.INCONCLUSIVE, result.overall)

    async def test_scanner_alone_requires_stable_fingerprint_delta(self) -> None:
        plan = self._plan(poc=False, scanner=True)
        baseline = await self.oracle.prepare_baseline(self.task, plan)
        self.assertTrue(baseline.usable)

        fixed = await self.oracle.validate(
            _candidate(self.task.task_id, CORRECT_DIFF),
            self.task,
            plan,
            baseline,
        )
        unchanged = await self.oracle.validate(
            _candidate(self.task.task_id, NOOP_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.VERIFIED_FIX, fixed.overall)
        self.assertEqual(OverallVerdict.REJECTED, unchanged.overall)

    async def test_patch_and_build_failures_are_rejected_not_verified(self) -> None:
        plan = self._plan(poc=True, scanner=False)
        baseline = await self.oracle.prepare_baseline(self.task, plan)

        non_applying = await self.oracle.validate(
            _candidate(self.task.task_id, NON_APPLYING_DIFF),
            self.task,
            plan,
            baseline,
        )
        regression = await self.oracle.validate(
            _candidate(self.task.task_id, REGRESSION_DIFF),
            self.task,
            plan,
            baseline,
        )

        self.assertEqual(OverallVerdict.REJECTED, non_applying.overall)
        self.assertEqual(OverallVerdict.REJECTED, regression.overall)
        self.assertFalse(any(item.stage == "candidate.poc" for item in regression.stages))


if __name__ == "__main__":
    unittest.main()
