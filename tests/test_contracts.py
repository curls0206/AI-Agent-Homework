from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError

from vulnrepair.contracts import (
    SCHEMA_VERSION,
    BaselineResult,
    Budget,
    CodeLocation,
    CommandResult,
    CommandSpec,
    ContractError,
    CostSummary,
    CritiqueResult,
    CritiqueVerdict,
    EvaluationMetadata,
    LocalizationResult,
    OverallVerdict,
    PatchCandidate,
    RepairResult,
    SchemaVersionError,
    SecurityOutcome,
    SnapshotMetadata,
    StageResult,
    StageVerdict,
    TraceEvent,
    TrustedHarness,
    UnknownFieldError,
    ValidationPlan,
    ValidationResult,
    VulnTask,
    derive_candidate_id,
)

DIFF_LF = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-bad\n+good\n"


def location() -> CodeLocation:
    return CodeLocation(
        file_path="app.py",
        function_name="render",
        start_line=1,
        end_line=1,
        confidence=0.9,
        rationale="Known vulnerable sink",
    )


def candidate(diff: str = DIFF_LF) -> PatchCandidate:
    return PatchCandidate(
        task_id="task-1",
        diff=diff,
        target_location=location(),
        generated_by="fixture",
        rationale="Escape output",
    )


def repair_result() -> RepairResult:
    patch = candidate()
    command = CommandSpec(name="tests", argv=("python", "-m", "unittest"), timeout_seconds=10)
    command_result = CommandResult(
        command=command,
        verdict=StageVerdict.PASS,
        returncode=0,
        stdout="ok",
        duration_seconds=0.1,
        reason_code="completed",
    )
    stage = StageResult(
        stage="test",
        verdict=StageVerdict.PASS,
        reason_code="tests_passed",
        command_result=command_result,
        security_outcome=SecurityOutcome.CLEAN,
    )
    validation = ValidationResult(
        candidate_id=patch.candidate_id,
        stages=(stage,),
        overall=OverallVerdict.VERIFIED_FIX,
        summary="verified",
    )
    baseline_stage = StageResult(
        stage="baseline.poc",
        verdict=StageVerdict.PASS,
        reason_code="baseline_vulnerability_reproduced",
        command_result=command_result,
        security_outcome=SecurityOutcome.VULNERABLE,
    )
    baseline = BaselineResult(
        task_id="task-1",
        snapshot=SnapshotMetadata(commit="abc", tree_digest="tree", archive_sha256="archive"),
        stages=(baseline_stage,),
        usable=True,
        summary="baseline vulnerability evidence established",
    )
    trace = TraceEvent(sequence=0, event="candidate_validated", task_id="task-1")
    return RepairResult(
        run_id="run-1",
        input_fingerprint="a" * 64,
        task_id="task-1",
        baseline=baseline,
        chosen=patch,
        all_candidates=(patch,),
        validations=(validation,),
        attempts=1,
        cost=CostSummary(
            rounds=1,
            candidates_seen=1,
            candidates_validated=1,
            elapsed_seconds=0.2,
            model_calls=1,
            prompt_tokens=10,
            completion_tokens=5,
            cost_usd=0.001,
        ),
        trace=(trace,),
        budget=Budget(),
    )


class ContractRoundTripTests(unittest.TestCase):
    def test_nested_repair_result_round_trips(self) -> None:
        result = repair_result()
        restored = RepairResult.from_json(result.to_json())
        self.assertEqual(restored, result)
        self.assertEqual(restored.schema_version, SCHEMA_VERSION)
        self.assertEqual(
            restored.baseline.stages[0].reason_code,
            "baseline_vulnerability_reproduced",
        )

    def test_all_primary_persisted_roots_round_trip(self) -> None:
        task = VulnTask(
            task_id="task-1",
            cve_id="CVE-2026-1",
            cwe_id="CWE-79",
            description="XSS",
            repo_path="repo",
            language="python",
            affected_versions="<2",
            references=("https://example.invalid/advisory",),
        )
        metadata = EvaluationMetadata(task_id="task-1", fixing_commit="abc123", source="fixture")
        localized = LocalizationResult(task_id="task-1", candidates=(location(),))
        critique = CritiqueResult(
            candidate_id=candidate().candidate_id, verdict=CritiqueVerdict.PASS
        )
        trusted_harness = TrustedHarness(root="/trusted/harness", digest_sha256="b" * 64)
        plan = ValidationPlan(
            build_commands=(CommandSpec(name="build", argv=("python", "-m", "compileall")),),
            poc_command=CommandSpec(name="poc", argv=("python", "/trusted/harness/poc.py")),
            harness=trusted_harness,
            target_finding="xss-sink",
        )
        snapshot = SnapshotMetadata(commit="abc", tree_digest="tree", archive_sha256="archive")
        baseline = BaselineResult(task_id="task-1", snapshot=snapshot, stages=(), usable=True)
        values = (
            task,
            metadata,
            localized,
            critique,
            trusted_harness,
            plan,
            snapshot,
            baseline,
        )
        for value in values:
            with self.subTest(contract=type(value).__name__):
                self.assertEqual(type(value).from_json(value.to_json()), value)

    def test_unknown_and_unsupported_fields_are_rejected(self) -> None:
        payload = repair_result().to_dict()
        payload["unexpected"] = True
        with self.assertRaises(UnknownFieldError):
            RepairResult.from_dict(payload)

        payload = repair_result().to_dict()
        payload["schema_version"] = "99"
        with self.assertRaises(SchemaVersionError):
            RepairResult.from_dict(payload)

        payload = repair_result().to_dict()
        del payload["schema_version"]
        with self.assertRaises(SchemaVersionError):
            RepairResult.from_dict(payload)

    def test_nested_unknown_field_is_rejected(self) -> None:
        payload = repair_result().to_dict()
        payload["chosen"]["surprise"] = "no"
        with self.assertRaises(UnknownFieldError):
            RepairResult.from_dict(payload)

    def test_runtime_task_rejects_evaluation_metadata(self) -> None:
        payload = VulnTask(
            task_id="task-1",
            cve_id=None,
            cwe_id="CWE-79",
            description="XSS",
            repo_path="repo",
            language="python",
            affected_versions="all",
        ).to_dict()
        payload["fixing_commit"] = "secret-ground-truth"
        with self.assertRaises(UnknownFieldError):
            VulnTask.from_dict(payload)
        self.assertNotIn("fixing_commit", json.dumps(repair_result().to_dict()))

    def test_security_commands_require_a_strict_trusted_harness(self) -> None:
        command = CommandSpec(name="poc", argv=("python", "poc.py"))
        with self.assertRaises(ContractError):
            ValidationPlan(poc_command=command)
        with self.assertRaises(ContractError):
            ValidationPlan(scanner_command=command)
        with self.assertRaises(ContractError):
            TrustedHarness(root="/trusted/harness", digest_sha256="A" * 64)
        with self.assertRaises(ContractError):
            TrustedHarness(root="/trusted/harness", digest_sha256="f" * 63)

    def test_repair_result_requires_lowercase_sha256_input_fingerprint(self) -> None:
        payload = repair_result().to_dict()
        payload["input_fingerprint"] = "A" * 64
        with self.assertRaises(ContractError):
            RepairResult.from_dict(payload)


class CandidateIdentityTests(unittest.TestCase):
    def test_candidate_id_uses_normalized_diff_sha256(self) -> None:
        lf = candidate(DIFF_LF)
        crlf = candidate(DIFF_LF.replace("\n", "\r\n"))
        self.assertEqual(lf.candidate_id, crlf.candidate_id)
        self.assertEqual(lf.diff, DIFF_LF)
        self.assertEqual(
            lf.candidate_id,
            hashlib.sha256(DIFF_LF.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(derive_candidate_id(DIFF_LF), lf.candidate_id)

    def test_supplied_candidate_id_must_match(self) -> None:
        with self.assertRaises(ContractError):
            PatchCandidate(task_id="task-1", diff=DIFF_LF, candidate_id="0" * 64)

    def test_contracts_are_frozen(self) -> None:
        patch = candidate()
        with self.assertRaises(FrozenInstanceError):
            patch.rationale = "changed"  # type: ignore[misc]

    def test_invalid_invariants_are_rejected(self) -> None:
        with self.assertRaises(ContractError):
            Budget(max_candidates=0)
        with self.assertRaises(ContractError):
            CodeLocation(
                file_path="x.py",
                function_name=None,
                start_line=3,
                end_line=2,
                confidence=0.5,
                rationale="bad range",
            )

    def test_non_finite_numbers_are_rejected_and_never_parsed_as_json(self) -> None:
        invalid_factories = (
            lambda: Budget(max_elapsed_seconds=float("nan")),
            lambda: Budget(max_cost_usd=float("inf")),
            lambda: CostSummary(elapsed_seconds=float("nan")),
            lambda: CostSummary(persistence_seconds=float("inf")),
            lambda: CostSummary(cost_usd=float("nan")),
            lambda: CommandSpec(name="x", argv=("x",), timeout_seconds=float("nan")),
            lambda: CommandResult(
                command=CommandSpec(name="x", argv=("x",)),
                verdict=StageVerdict.PASS,
                duration_seconds=float("inf"),
            ),
            lambda: CodeLocation(
                file_path="x.py",
                function_name=None,
                start_line=1,
                end_line=1,
                confidence=float("nan"),
                rationale="fixture",
            ),
        )
        for factory in invalid_factories:
            with self.subTest(factory=factory), self.assertRaises(ContractError):
                factory()

        payload = (
            repair_result().to_json().replace('"elapsed_seconds": 0.2', '"elapsed_seconds": NaN')
        )
        with self.assertRaises(ContractError):
            RepairResult.from_json(payload)


if __name__ == "__main__":
    unittest.main()
