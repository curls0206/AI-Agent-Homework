from __future__ import annotations

import hashlib
import json
from enum import IntEnum
from pathlib import Path
from typing import Any, Sequence

from .contracts import (
    BaselineResult,
    CommandResult,
    CommandSpec,
    OverallVerdict,
    PatchCandidate,
    SecurityOutcome,
    SnapshotMetadata,
    StageResult,
    StageVerdict,
    ValidationPlan,
    ValidationResult,
    VulnTask,
)
from .harness import HarnessError, verify_harness_binding
from .patches import PatchApplyError, PatchPolicy, PatchPolicyError
from .ports import CommandRunnerProtocol
from .snapshot import SnapshotMaterializer

EVIDENCE_SCHEMA_VERSION = "1.0"


class _Gate(IntEnum):
    OK = 0
    INCONCLUSIVE = 1
    REJECTED = 2
    INFRA_ERROR = 3


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _enum_value(enum_type: type[Any], value: Any, fallback: Any) -> Any:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        return fallback


def _stage(
    name: str,
    verdict: StageVerdict,
    reason_code: str,
    *,
    security_outcome: SecurityOutcome | None = None,
    message: str = "",
    command_result: CommandResult | None = None,
    artifacts: tuple[str, ...] = (),
) -> StageResult:
    return StageResult(
        stage=name,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        command_result=command_result,
        security_outcome=security_outcome,
        artifacts=artifacts,
    )


def _skipped(name: str, reason_code: str) -> StageResult:
    return _stage(
        name,
        StageVerdict.SKIPPED,
        reason_code,
        security_outcome=SecurityOutcome.NOT_AVAILABLE,
    )


def _is_infrastructure(stage: StageResult) -> bool:
    return stage.verdict in (StageVerdict.INFRA_ERROR, StageVerdict.TIMEOUT)


def _stdout(stage: StageResult) -> str:
    if stage.command_result is None:
        return ""
    return stage.command_result.stdout


def _returncode(stage: StageResult) -> int | None:
    if stage.command_result is None:
        return None
    return stage.command_result.returncode


def _command_required(spec: CommandSpec | None) -> bool:
    return bool(spec is not None and getattr(spec, "required", True))


def _snapshot_matches(left: Any, right: Any) -> bool:
    return left is not None and right is not None and left == right


def _plan_marker(plan: ValidationPlan) -> str:
    digest = hashlib.sha256(plan.to_json(indent=None).encode("utf-8")).hexdigest()
    return f"validation-plan-sha256:{digest}"


class VerificationOracle:
    """Fail-closed verification pipeline.

    The runner is injected so production can use a hardened container while
    tests can remain completely offline.  Repository materialization and patch
    application are delegated to the safety layer; the Oracle owns ordering,
    evidence parsing, differential comparison, and final verdict semantics.
    """

    def __init__(
        self,
        runner: CommandRunnerProtocol,
        *,
        snapshot_materializer: SnapshotMaterializer | None = None,
        patch_policy: PatchPolicy | None = None,
    ) -> None:
        self._runner = runner
        self._snapshots = snapshot_materializer or SnapshotMaterializer()
        self._patches = patch_policy or PatchPolicy()

    async def prepare_baseline(self, task: VulnTask, plan: ValidationPlan) -> BaselineResult:
        stages: list[StageResult] = []
        snapshot = None

        harness_stage = self._check_harness("baseline.harness.initial", task, plan)
        stages.append(harness_stage)
        if harness_stage.verdict is StageVerdict.INFRA_ERROR:
            stages.extend(
                self._skip_sequence("baseline.build", plan.build_commands, "harness_failed")
            )
            stages.extend(
                self._skip_sequence("baseline.test", plan.test_commands, "harness_failed")
            )
            stages.extend(self._skip_security("baseline", plan, "harness_failed"))
            return BaselineResult(
                task_id=task.task_id,
                snapshot=None,
                stages=tuple(stages),
                usable=False,
                summary="trusted validation harness failed integrity checks",
            )

        try:
            with self._snapshots.materialize(Path(task.repo_path), task.base_ref) as materialized:
                snapshot = materialized.metadata
                stages.append(
                    _stage(
                        "baseline.snapshot.build",
                        StageVerdict.PASS,
                        "snapshot_materialized",
                        artifacts=(_plan_marker(plan),),
                    )
                )
                build_stages, build_gate = await self._run_sequence(
                    "baseline.build", plan.build_commands, materialized.root
                )
                stages.extend(build_stages)
                if build_gate is _Gate.OK:
                    test_stages, test_gate = await self._run_sequence(
                        "baseline.test", plan.test_commands, materialized.root
                    )
                    stages.extend(test_stages)
                else:
                    test_gate = build_gate
                    stages.extend(
                        self._skip_sequence(
                            "baseline.test",
                            plan.test_commands,
                            "blocked_by_build",
                        )
                    )
        except Exception as exc:
            stages.append(
                _stage(
                    "baseline.snapshot.build",
                    StageVerdict.INFRA_ERROR,
                    "snapshot_materialization_failed",
                    message=_text(exc),
                )
            )
            stages.extend(self._skip_security("baseline", plan, "snapshot_failed"))
            return BaselineResult(
                task_id=task.task_id,
                snapshot=None,
                stages=tuple(stages),
                usable=False,
                summary="baseline snapshot could not be materialized",
            )

        build_test_gate = max(build_gate, test_gate)
        if build_test_gate is not _Gate.OK:
            stages.extend(self._skip_security("baseline", plan, "build_or_tests_failed"))
            return BaselineResult(
                task_id=task.task_id,
                snapshot=snapshot,
                stages=tuple(stages),
                usable=False,
                summary="baseline build or regression tests did not pass",
            )

        try:
            with self._snapshots.materialize(Path(task.repo_path), task.base_ref) as materialized:
                if not _snapshot_matches(snapshot, materialized.metadata):
                    stages.append(
                        _stage(
                            "baseline.snapshot.security",
                            StageVerdict.INFRA_ERROR,
                            "snapshot_changed_during_baseline",
                        )
                    )
                    stages.extend(
                        self._skip_security("baseline", plan, "snapshot_identity_mismatch")
                    )
                    return BaselineResult(
                        task_id=task.task_id,
                        snapshot=snapshot,
                        stages=tuple(stages),
                        usable=False,
                        summary="baseline snapshot identity changed",
                    )
                stages.append(
                    _stage(
                        "baseline.snapshot.security",
                        StageVerdict.PASS,
                        "snapshot_materialized",
                    )
                )
                harness_stage = self._check_harness("baseline.harness.security", task, plan)
                stages.append(harness_stage)
                if harness_stage.verdict is StageVerdict.INFRA_ERROR:
                    stages.extend(self._skip_security("baseline", plan, "harness_failed"))
                    return BaselineResult(
                        task_id=task.task_id,
                        snapshot=snapshot,
                        stages=tuple(stages),
                        usable=False,
                        summary="trusted validation harness changed before security validation",
                    )
                security_stages = await self._run_security("baseline", plan, materialized.root)
                stages.extend(security_stages)
        except Exception as exc:
            stages.append(
                _stage(
                    "baseline.snapshot.security",
                    StageVerdict.INFRA_ERROR,
                    "snapshot_materialization_failed",
                    message=_text(exc),
                )
            )
            stages.extend(self._skip_security("baseline", plan, "snapshot_failed"))
            return BaselineResult(
                task_id=task.task_id,
                snapshot=snapshot,
                stages=tuple(stages),
                usable=False,
                summary="baseline security workspace could not be materialized",
            )

        usable, summary = self._baseline_security_usable(plan, security_stages)
        return BaselineResult(
            task_id=task.task_id,
            snapshot=snapshot,
            stages=tuple(stages),
            usable=usable,
            summary=summary,
        )

    async def validate(
        self,
        candidate: PatchCandidate,
        task: VulnTask,
        plan: ValidationPlan,
        baseline: BaselineResult,
    ) -> ValidationResult:
        stages: list[StageResult] = []
        if baseline.task_id != task.task_id:
            stages.append(
                _stage(
                    "candidate.baseline",
                    StageVerdict.INFRA_ERROR,
                    "baseline_task_mismatch",
                )
            )
            return self._validation(
                candidate,
                stages,
                OverallVerdict.INFRA_ERROR,
                "baseline belongs to another task",
            )

        expected_plan_marker = _plan_marker(plan)
        if not any(expected_plan_marker in stage.artifacts for stage in baseline.stages):
            stages.append(
                _stage(
                    "candidate.baseline",
                    StageVerdict.INFRA_ERROR,
                    "baseline_plan_mismatch",
                )
            )
            return self._validation(
                candidate,
                stages,
                OverallVerdict.INFRA_ERROR,
                "baseline was prepared with a different validation plan",
                snapshot=baseline.snapshot,
            )

        if not baseline.usable:
            baseline_infra = any(_is_infrastructure(item) for item in baseline.stages)
            verdict = OverallVerdict.INFRA_ERROR if baseline_infra else OverallVerdict.INCONCLUSIVE
            stages.append(
                _stage(
                    "candidate.baseline",
                    StageVerdict.INFRA_ERROR if baseline_infra else StageVerdict.SKIPPED,
                    "baseline_unusable",
                )
            )
            return self._validation(
                candidate,
                stages,
                verdict,
                "candidate not run: baseline unusable",
                snapshot=baseline.snapshot,
            )

        stages.append(_stage("candidate.baseline", StageVerdict.PASS, "baseline_usable"))
        harness_stage = self._check_harness("candidate.harness.initial", task, plan)
        stages.append(harness_stage)
        if harness_stage.verdict is StageVerdict.INFRA_ERROR:
            stages.extend(
                self._skip_sequence("candidate.build", plan.build_commands, "harness_failed")
            )
            stages.extend(
                self._skip_sequence("candidate.test", plan.test_commands, "harness_failed")
            )
            stages.extend(self._skip_security("candidate", plan, "harness_failed"))
            return self._validation(
                candidate,
                stages,
                OverallVerdict.INFRA_ERROR,
                "trusted validation harness failed integrity checks",
                snapshot=baseline.snapshot,
            )

        try:
            with self._snapshots.materialize(Path(task.repo_path), task.base_ref) as materialized:
                if not _snapshot_matches(baseline.snapshot, materialized.metadata):
                    stages.append(
                        _stage(
                            "candidate.snapshot.build",
                            StageVerdict.INFRA_ERROR,
                            "snapshot_differs_from_baseline",
                        )
                    )
                    return self._validation(
                        candidate,
                        stages,
                        OverallVerdict.INFRA_ERROR,
                        "candidate snapshot differs from baseline",
                        snapshot=baseline.snapshot,
                    )
                stages.append(
                    _stage(
                        "candidate.snapshot.build",
                        StageVerdict.PASS,
                        "snapshot_materialized",
                    )
                )
                apply_stage = self._apply_patch(
                    "candidate.patch.build", candidate, task, materialized.root
                )
                stages.append(apply_stage)
                if apply_stage.verdict is not StageVerdict.PASS:
                    return self._validation(
                        candidate,
                        stages,
                        OverallVerdict.INFRA_ERROR
                        if _is_infrastructure(apply_stage)
                        else OverallVerdict.REJECTED,
                        "candidate patch could not be applied",
                        snapshot=baseline.snapshot,
                    )

                build_stages, build_gate = await self._run_sequence(
                    "candidate.build", plan.build_commands, materialized.root
                )
                stages.extend(build_stages)
                if build_gate is _Gate.OK:
                    test_stages, test_gate = await self._run_sequence(
                        "candidate.test", plan.test_commands, materialized.root
                    )
                    stages.extend(test_stages)
                else:
                    test_gate = build_gate
                    stages.extend(
                        self._skip_sequence(
                            "candidate.test",
                            plan.test_commands,
                            "blocked_by_build",
                        )
                    )
        except Exception as exc:
            stages.append(
                _stage(
                    "candidate.snapshot.build",
                    StageVerdict.INFRA_ERROR,
                    "workspace_preparation_failed",
                    message=_text(exc),
                )
            )
            return self._validation(
                candidate,
                stages,
                OverallVerdict.INFRA_ERROR,
                "candidate build workspace failed",
                snapshot=baseline.snapshot,
            )

        build_test_gate = max(build_gate, test_gate)
        if build_test_gate is not _Gate.OK:
            verdict = self._overall_for_gate(build_test_gate)
            return self._validation(
                candidate,
                stages,
                verdict,
                "candidate build or regression tests did not pass",
                snapshot=baseline.snapshot,
            )

        try:
            with self._snapshots.materialize(Path(task.repo_path), task.base_ref) as materialized:
                if not _snapshot_matches(baseline.snapshot, materialized.metadata):
                    stages.append(
                        _stage(
                            "candidate.snapshot.security",
                            StageVerdict.INFRA_ERROR,
                            "snapshot_differs_from_baseline",
                        )
                    )
                    return self._validation(
                        candidate,
                        stages,
                        OverallVerdict.INFRA_ERROR,
                        "candidate security snapshot differs from baseline",
                        snapshot=baseline.snapshot,
                    )
                stages.append(
                    _stage(
                        "candidate.snapshot.security",
                        StageVerdict.PASS,
                        "snapshot_materialized",
                    )
                )
                apply_stage = self._apply_patch(
                    "candidate.patch.security", candidate, task, materialized.root
                )
                stages.append(apply_stage)
                if apply_stage.verdict is not StageVerdict.PASS:
                    return self._validation(
                        candidate,
                        stages,
                        OverallVerdict.INFRA_ERROR
                        if _is_infrastructure(apply_stage)
                        else OverallVerdict.REJECTED,
                        "candidate patch could not be applied to security workspace",
                        snapshot=baseline.snapshot,
                    )
                harness_stage = self._check_harness("candidate.harness.security", task, plan)
                stages.append(harness_stage)
                if harness_stage.verdict is StageVerdict.INFRA_ERROR:
                    stages.extend(self._skip_security("candidate", plan, "harness_failed"))
                    return self._validation(
                        candidate,
                        stages,
                        OverallVerdict.INFRA_ERROR,
                        "trusted validation harness changed before security validation",
                        snapshot=baseline.snapshot,
                    )
                security_stages = await self._run_security("candidate", plan, materialized.root)
                stages.extend(security_stages)
        except Exception as exc:
            stages.append(
                _stage(
                    "candidate.snapshot.security",
                    StageVerdict.INFRA_ERROR,
                    "workspace_preparation_failed",
                    message=_text(exc),
                )
            )
            return self._validation(
                candidate,
                stages,
                OverallVerdict.INFRA_ERROR,
                "candidate security workspace failed",
                snapshot=baseline.snapshot,
            )

        overall, summary = self._candidate_security_verdict(plan, baseline.stages, security_stages)
        return self._validation(
            candidate,
            stages,
            overall,
            summary,
            snapshot=baseline.snapshot,
        )

    async def _run_sequence(
        self,
        prefix: str,
        specs: Sequence[CommandSpec],
        workspace: Path,
    ) -> tuple[list[StageResult], _Gate]:
        if not specs:
            return [_skipped(prefix, "no_commands_configured")], _Gate.OK

        stages: list[StageResult] = []
        gate = _Gate.OK
        halted = False
        for index, spec in enumerate(specs):
            name = f"{prefix}.{index}"
            if halted:
                stages.append(_skipped(name, "blocked_by_previous_required_stage"))
                continue
            result = await self._execute(name, spec, workspace)
            stages.append(result)
            if not _command_required(spec) or result.verdict is StageVerdict.PASS:
                continue
            stage_gate = self._gate_for_stage(result)
            gate = max(gate, stage_gate)
            halted = True
        return stages, gate

    def _check_harness(
        self,
        stage_name: str,
        task: VulnTask,
        plan: ValidationPlan,
    ) -> StageResult:
        """Bind configured security evidence to an immutable external harness."""

        runner_exposes_harness = hasattr(self._runner, "harness_dir")
        try:
            observed = verify_harness_binding(
                repo_path=task.repo_path,
                plan=plan,
                runner_harness_dir=getattr(self._runner, "harness_dir", None),
                runner_exposes_harness=runner_exposes_harness,
            )
        except HarnessError as exc:
            return _stage(
                stage_name,
                StageVerdict.INFRA_ERROR,
                exc.reason_code,
                security_outcome=SecurityOutcome.HARNESS_ERROR,
                message=_text(exc),
            )
        if observed is None:
            return _skipped(stage_name, "security_harness_not_configured")
        return _stage(
            stage_name,
            StageVerdict.PASS,
            "trusted_harness_verified",
            artifacts=(f"harness-sha256:{observed}",),
        )

    async def _execute(self, name: str, spec: CommandSpec, workspace: Path) -> StageResult:
        try:
            runner_result: object = await self._runner.run(spec, workspace)
        except TimeoutError as exc:
            return _stage(
                name,
                StageVerdict.TIMEOUT,
                "runner_timeout",
                message=_text(exc),
            )
        except (FileNotFoundError, OSError) as exc:
            return _stage(
                name,
                StageVerdict.INFRA_ERROR,
                "runner_executable_missing",
                message=_text(exc),
            )
        except Exception as exc:
            return _stage(
                name,
                StageVerdict.INFRA_ERROR,
                "runner_exception",
                message=_text(exc),
            )

        if not isinstance(runner_result, CommandResult):
            return _stage(
                name,
                StageVerdict.INFRA_ERROR,
                "invalid_runner_result",
                message=(f"runner returned {type(runner_result).__name__}, expected CommandResult"),
            )
        result = runner_result
        verdict = _enum_value(
            StageVerdict,
            getattr(result, "verdict", None),
            StageVerdict.INFRA_ERROR,
        )
        returncode = getattr(result, "returncode", None)
        if verdict is StageVerdict.PASS and returncode not in (None, 0):
            verdict = StageVerdict.INFRA_ERROR
            reason = "inconsistent_runner_result"
        else:
            reason = _text(getattr(result, "reason_code", "")) or (
                "command_passed" if verdict is StageVerdict.PASS else "command_failed"
            )
        return _stage(
            name,
            verdict,
            reason,
            command_result=result,
        )

    async def _run_security(
        self, phase: str, plan: ValidationPlan, workspace: Path
    ) -> list[StageResult]:
        stages: list[StageResult] = []
        if plan.poc_command is None:
            stages.append(_skipped(f"{phase}.poc", "poc_not_configured"))
        else:
            stages.append(await self._run_poc(f"{phase}.poc", plan.poc_command, workspace, phase))

        if plan.scanner_command is None:
            stages.append(_skipped(f"{phase}.scanner", "scanner_not_configured"))
        else:
            stages.append(
                await self._run_scanner(
                    f"{phase}.scanner",
                    plan.scanner_command,
                    workspace,
                    phase,
                    plan.target_finding,
                )
            )
        return stages

    async def _run_poc(
        self,
        name: str,
        spec: CommandSpec,
        workspace: Path,
        phase: str,
    ) -> StageResult:
        process = await self._execute(name, spec, workspace)
        process = self._security_process_stage(process)
        if process.verdict is not StageVerdict.PASS:
            return process

        try:
            evidence = self._parse_evidence(_stdout(process))
            outcome = SecurityOutcome(evidence["outcome"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return self._replace_stage(
                process,
                verdict=StageVerdict.INFRA_ERROR,
                reason_code="malformed_poc_evidence",
                security_outcome=SecurityOutcome.HARNESS_ERROR,
                message=self._join_error(process.message, exc),
            )

        if outcome is SecurityOutcome.NOT_AVAILABLE:
            return self._replace_stage(
                process,
                verdict=StageVerdict.SKIPPED,
                reason_code="poc_evidence_not_available",
                security_outcome=outcome,
            )
        if outcome is SecurityOutcome.HARNESS_ERROR:
            return self._replace_stage(
                process,
                verdict=StageVerdict.INFRA_ERROR,
                reason_code="poc_harness_error",
                security_outcome=outcome,
            )

        if phase == "baseline":
            passed = outcome is SecurityOutcome.VULNERABLE
            reason = "baseline_vulnerability_reproduced" if passed else "baseline_not_vulnerable"
        else:
            passed = outcome in (SecurityOutcome.BLOCKED, SecurityOutcome.CLEAN)
            reason = "patched_exploit_blocked" if passed else "patched_exploit_persists"
        return self._replace_stage(
            process,
            verdict=StageVerdict.PASS if passed else StageVerdict.FAIL,
            reason_code=reason,
            security_outcome=outcome,
        )

    async def _run_scanner(
        self,
        name: str,
        spec: CommandSpec,
        workspace: Path,
        phase: str,
        target_finding: str | None,
    ) -> StageResult:
        process = await self._execute(name, spec, workspace)
        process = self._security_process_stage(process)
        if process.verdict is not StageVerdict.PASS:
            return process
        if not target_finding:
            return self._replace_stage(
                process,
                verdict=StageVerdict.INFRA_ERROR,
                reason_code="scanner_target_finding_missing",
                security_outcome=SecurityOutcome.HARNESS_ERROR,
            )

        try:
            evidence = self._parse_evidence(_stdout(process))
            raw_findings = evidence["findings"]
            if not isinstance(raw_findings, list):
                raise TypeError("findings must be a list")
            findings: set[str] = set()
            for item in raw_findings:
                if isinstance(item, str):
                    findings.add(item)
                elif isinstance(item, dict) and isinstance(item.get("fingerprint"), str):
                    findings.add(item["fingerprint"])
                else:
                    raise TypeError("each finding must expose a fingerprint")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return self._replace_stage(
                process,
                verdict=StageVerdict.INFRA_ERROR,
                reason_code="malformed_scanner_evidence",
                security_outcome=SecurityOutcome.HARNESS_ERROR,
                message=self._join_error(process.message, exc),
            )

        present = target_finding in findings
        outcome = SecurityOutcome.FINDING_PRESENT if present else SecurityOutcome.CLEAN
        passed = present if phase == "baseline" else not present
        if phase == "baseline":
            reason = (
                "baseline_target_finding_present" if passed else "baseline_target_finding_absent"
            )
        else:
            reason = (
                "patched_target_finding_absent" if passed else "patched_target_finding_persists"
            )
        return self._replace_stage(
            process,
            verdict=StageVerdict.PASS if passed else StageVerdict.FAIL,
            reason_code=reason,
            security_outcome=outcome,
        )

    @staticmethod
    def _parse_evidence(stdout: str) -> dict[str, Any]:
        value = json.loads(stdout)
        if not isinstance(value, dict):
            raise TypeError("evidence must be a JSON object")
        if value.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported evidence schema")
        if value.get("harness_ok") is not True:
            raise ValueError("harness did not report healthy execution")
        return value

    @staticmethod
    def _security_process_stage(process: StageResult) -> StageResult:
        if process.verdict is StageVerdict.PASS and _returncode(process) in (None, 0):
            return process
        verdict = (
            StageVerdict.TIMEOUT
            if process.verdict is StageVerdict.TIMEOUT
            else StageVerdict.INFRA_ERROR
        )
        return VerificationOracle._replace_stage(
            process,
            verdict=verdict,
            reason_code="security_harness_process_failed",
            security_outcome=SecurityOutcome.HARNESS_ERROR,
        )

    def _apply_patch(
        self,
        name: str,
        candidate: PatchCandidate,
        task: VulnTask,
        workspace: Path,
    ) -> StageResult:
        try:
            self._patches.apply(candidate, task.task_id, workspace)
            return _stage(name, StageVerdict.PASS, "patch_applied")
        except PatchPolicyError as exc:
            return _stage(
                name,
                StageVerdict.FAIL,
                exc.reason_code,
                message=_text(exc),
            )
        except PatchApplyError as exc:
            infrastructure_codes = {
                "git_missing",
                "git_spawn_error",
                "invalid_workspace",
                "patch_apply_timeout",
            }
            return _stage(
                name,
                StageVerdict.INFRA_ERROR
                if exc.reason_code in infrastructure_codes
                else StageVerdict.FAIL,
                exc.reason_code,
                message=_text(exc),
            )
        except Exception as exc:
            return _stage(
                name,
                StageVerdict.INFRA_ERROR,
                "patch_application_error",
                message=_text(exc),
            )

    @staticmethod
    def _baseline_security_usable(
        plan: ValidationPlan, stages: Sequence[StageResult]
    ) -> tuple[bool, str]:
        by_name = {item.stage.rsplit(".", 1)[-1]: item for item in stages}
        required = {
            "poc": plan.poc_command,
            "scanner": plan.scanner_command,
        }
        required_count = 0
        for name, spec in required.items():
            if not _command_required(spec):
                continue
            required_count += 1
            result = by_name.get(name)
            if result is None or result.verdict is not StageVerdict.PASS:
                if result is not None and _is_infrastructure(result):
                    return False, "baseline security harness failed"
                return False, "baseline vulnerability evidence was not established"
        if required_count == 0:
            return False, "no required baseline security signal is configured"
        return True, "baseline vulnerability evidence established"

    @staticmethod
    def _candidate_security_verdict(
        plan: ValidationPlan,
        baseline_stages: Sequence[StageResult],
        candidate_stages: Sequence[StageResult],
    ) -> tuple[OverallVerdict, str]:
        baseline = {item.stage.rsplit(".", 1)[-1]: item for item in baseline_stages}
        candidate = {item.stage.rsplit(".", 1)[-1]: item for item in candidate_stages}
        specifications = {
            "poc": plan.poc_command,
            "scanner": plan.scanner_command,
        }

        passed_required = 0
        required_total = 0
        for name, spec in specifications.items():
            if spec is None:
                continue
            before = baseline.get(name)
            after = candidate.get(name)

            if after is not None and (
                after.security_outcome is SecurityOutcome.VULNERABLE
                or after.security_outcome is SecurityOutcome.FINDING_PRESENT
            ):
                return OverallVerdict.REJECTED, "security signal persists after patch"

            if not _command_required(spec):
                continue
            required_total += 1
            if before is None or before.verdict is not StageVerdict.PASS:
                return OverallVerdict.INCONCLUSIVE, "baseline evidence is missing"
            if after is None:
                return OverallVerdict.INCONCLUSIVE, "patched evidence is missing"
            if _is_infrastructure(after):
                return OverallVerdict.INFRA_ERROR, "security harness failed"
            if after.verdict is not StageVerdict.PASS:
                return OverallVerdict.INCONCLUSIVE, "patched evidence is inconclusive"
            passed_required += 1

        if required_total == 0 or passed_required == 0:
            return OverallVerdict.INCONCLUSIVE, "no required differential security signal passed"
        if passed_required != required_total:
            return OverallVerdict.INCONCLUSIVE, "not every required security signal passed"
        return OverallVerdict.VERIFIED_FIX, "required differential security evidence passed"

    @staticmethod
    def _skip_sequence(prefix: str, specs: Sequence[CommandSpec], reason: str) -> list[StageResult]:
        if not specs:
            return [_skipped(prefix, reason)]
        return [_skipped(f"{prefix}.{index}", reason) for index, _ in enumerate(specs)]

    @staticmethod
    def _skip_security(phase: str, plan: ValidationPlan, reason: str) -> list[StageResult]:
        return [
            _skipped(f"{phase}.poc", reason),
            _skipped(f"{phase}.scanner", reason),
        ]

    @staticmethod
    def _gate_for_stage(stage: StageResult) -> _Gate:
        if stage.verdict is StageVerdict.PASS:
            return _Gate.OK
        if _is_infrastructure(stage):
            return _Gate.INFRA_ERROR
        if stage.verdict is StageVerdict.SKIPPED:
            return _Gate.INCONCLUSIVE
        return _Gate.REJECTED

    @staticmethod
    def _overall_for_gate(gate: _Gate) -> OverallVerdict:
        if gate is _Gate.INFRA_ERROR:
            return OverallVerdict.INFRA_ERROR
        if gate is _Gate.REJECTED:
            return OverallVerdict.REJECTED
        return OverallVerdict.INCONCLUSIVE

    @staticmethod
    def _replace_stage(
        original: StageResult,
        *,
        verdict: StageVerdict,
        reason_code: str,
        security_outcome: SecurityOutcome,
        message: str | None = None,
    ) -> StageResult:
        return _stage(
            original.stage,
            verdict,
            reason_code,
            security_outcome=security_outcome,
            message=original.message if message is None else message,
            command_result=original.command_result,
            artifacts=original.artifacts,
        )

    @staticmethod
    def _join_error(existing: str, error: Exception) -> str:
        detail = _text(error)
        return f"{existing}\n{detail}".strip()

    @staticmethod
    def _validation(
        candidate: PatchCandidate,
        stages: Sequence[StageResult],
        overall: OverallVerdict,
        summary: str,
        *,
        snapshot: SnapshotMetadata | None = None,
    ) -> ValidationResult:
        return ValidationResult(
            candidate_id=candidate.candidate_id,
            stages=tuple(stages),
            overall=overall,
            summary=summary,
            snapshot=snapshot,
        )


__all__ = ["EVIDENCE_SCHEMA_VERSION", "VerificationOracle"]
