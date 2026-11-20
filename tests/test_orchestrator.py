from __future__ import annotations

import asyncio
import time
import unittest
from dataclasses import dataclass, field

from vulnrepair.adapters import InMemoryRepairMemory, PolicyCritic, StaticGenerator, StaticLocalizer
from vulnrepair.contracts import (
    BaselineResult,
    Budget,
    CodeLocation,
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
from vulnrepair.orchestrator import BudgetDeadlineExceeded, RepairOrchestrator, _before_deadline

SMALL_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-old
+new
"""

LARGE_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
-old
-unsafe
+new
+safe
"""


def make_task() -> VulnTask:
    return VulnTask(
        task_id="task-orchestrator",
        cve_id=None,
        cwe_id="CWE-79",
        description="HTML injection",
        repo_path="repo",
        language="python",
        affected_versions="1.0",
    )


def make_location() -> CodeLocation:
    return CodeLocation(
        file_path="app.py",
        function_name="render",
        start_line=1,
        end_line=2,
        confidence=1.0,
        rationale="fixture",
    )


@dataclass
class FakeOracle:
    verdicts: dict[str, OverallVerdict]
    baseline_usable: bool = True
    baseline_stages: tuple[StageResult, ...] = ()
    calls: list[str] = field(default_factory=list)

    async def prepare_baseline(self, task: VulnTask, plan: ValidationPlan) -> BaselineResult:
        return BaselineResult(
            task_id=task.task_id,
            snapshot=SnapshotMetadata(commit="c", tree_digest="t", archive_sha256="a"),
            stages=self.baseline_stages,
            usable=self.baseline_usable,
            summary="baseline ready" if self.baseline_usable else "not vulnerable",
        )

    async def validate(self, candidate, task, plan, baseline) -> ValidationResult:
        self.calls.append(candidate.candidate_id)
        verdict = self.verdicts.get(candidate.candidate_id, OverallVerdict.REJECTED)
        return ValidationResult(
            candidate_id=candidate.candidate_id,
            stages=(),
            overall=verdict,
            summary=verdict.value,
        )


@dataclass
class FakeUsage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    budget_violations: int = 0


@dataclass
class AccountingGenerator:
    candidate: PatchCandidate
    usage: FakeUsage = field(default_factory=FakeUsage)
    reservations: list[tuple[int, float]] = field(default_factory=list)

    async def generate(self, task, locations, failures, limit, max_cost_usd):
        del task, locations, failures
        self.reservations.append((limit, max_cost_usd))
        if limit <= 0 or max_cost_usd < 0.01:
            return ()
        self.usage.calls += 1
        self.usage.prompt_tokens += 10
        self.usage.completion_tokens += 5
        self.usage.cost_usd += 0.01
        return (self.candidate,)


@dataclass
class FlakyGenerator:
    candidate: PatchCandidate
    failures_before_success: int
    attempts: int = 0
    last_errors: tuple[str, ...] = ()

    async def generate(self, task, locations, failures, limit, max_cost_usd):
        del task, locations, failures, limit, max_cost_usd
        self.attempts += 1
        if self.attempts <= self.failures_before_success:
            self.last_errors = ("model sample 1: ValueError: no valid changes found in JSON",)
            return ()
        self.last_errors = ()
        return (self.candidate,)


class BlockingMemory(InMemoryRepairMemory):
    async def remember(self, task, candidate, validation) -> None:
        await asyncio.sleep(5)
        await super().remember(task, candidate, validation)


class SlowBaselineOracle(FakeOracle):
    async def prepare_baseline(self, task: VulnTask, plan: ValidationPlan) -> BaselineResult:
        await asyncio.sleep(5)
        return await super().prepare_baseline(task, plan)


@dataclass
class SlowCandidateOracle(FakeOracle):
    slow_candidate_id: str = ""

    async def validate(self, candidate, task, plan, baseline) -> ValidationResult:
        if candidate.candidate_id == self.slow_candidate_id:
            await asyncio.sleep(5)
        return await super().validate(candidate, task, plan, baseline)


class SlowStore:
    async def save(self, result, *, deadline=None):
        del deadline
        await asyncio.sleep(5)
        return result

    async def load(self, run_dir):
        raise NotImplementedError


class OrchestratorTests(unittest.IsolatedAsyncioTestCase):
    async def test_deadline_wrapper_distinguishes_inner_timeout_from_budget_expiry(self) -> None:
        async def provider_timeout() -> None:
            raise TimeoutError("provider timeout")

        with self.assertRaises(TimeoutError) as provider_error:
            await _before_deadline(provider_timeout, time.monotonic() + 1)
        self.assertIs(type(provider_error.exception), TimeoutError)

        async def slow_operation() -> None:
            await asyncio.sleep(1)

        with self.assertRaises(BudgetDeadlineExceeded):
            await _before_deadline(slow_operation, time.monotonic() + 0.02)

    async def test_selects_smallest_verified_patch_after_fixed_batch(self) -> None:
        small = PatchCandidate(
            task_id=make_task().task_id, diff=SMALL_DIFF, target_location=make_location()
        )
        large = PatchCandidate(
            task_id=make_task().task_id, diff=LARGE_DIFF, target_location=make_location()
        )
        oracle = FakeOracle(
            {
                small.candidate_id: OverallVerdict.VERIFIED_FIX,
                large.candidate_id: OverallVerdict.VERIFIED_FIX,
            }
        )
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=StaticGenerator((large, small)),
            critic=PolicyCritic(),
            oracle=oracle,
            memory=InMemoryRepairMemory(),
            budget=Budget(max_rounds=1, max_candidates=2, max_validations=2, batch_size=2),
        )
        result = await orchestrator.repair(make_task(), ValidationPlan())
        self.assertEqual(small.candidate_id, result.chosen.candidate_id)
        self.assertEqual(2, len(result.validations))
        self.assertEqual(sorted(oracle.calls), oracle.calls)

    async def test_unusable_baseline_stops_before_generation(self) -> None:
        candidate = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        oracle = FakeOracle({}, baseline_usable=False)
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=StaticGenerator((candidate,)),
            critic=PolicyCritic(),
            oracle=oracle,
            memory=InMemoryRepairMemory(),
            budget=Budget(),
        )
        result = await orchestrator.repair(make_task(), ValidationPlan())
        self.assertIsNone(result.chosen)
        self.assertEqual((), result.all_candidates)
        self.assertEqual([], oracle.calls)

    async def test_transient_provider_failure_is_retried_in_the_next_round(self) -> None:
        candidate = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        generator = FlakyGenerator(candidate, failures_before_success=1)
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=generator,
            critic=PolicyCritic(),
            oracle=FakeOracle({candidate.candidate_id: OverallVerdict.VERIFIED_FIX}),
            memory=InMemoryRepairMemory(),
            budget=Budget(max_rounds=3),
        )
        result = await orchestrator.repair(make_task(), ValidationPlan())
        self.assertEqual(candidate.candidate_id, result.chosen.candidate_id)
        self.assertEqual(2, generator.attempts)
        events = [event.event for event in result.trace]
        self.assertEqual(1, events.count("round_empty"))
        self.assertIn("provider_errors", events)

    async def test_permanent_provider_failure_is_bounded_by_the_round_limit(self) -> None:
        candidate = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        generator = FlakyGenerator(candidate, failures_before_success=100)
        oracle = FakeOracle({})
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=generator,
            critic=PolicyCritic(),
            oracle=oracle,
            memory=InMemoryRepairMemory(),
            budget=Budget(max_rounds=3),
        )
        result = await orchestrator.repair(make_task(), ValidationPlan())
        self.assertIsNone(result.chosen)
        self.assertEqual(3, generator.attempts)
        self.assertEqual([], oracle.calls)

    async def test_candidate_budget_is_reserved_deterministically(self) -> None:
        first = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        second = PatchCandidate(task_id=make_task().task_id, diff=LARGE_DIFF)
        oracle = FakeOracle({})
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=StaticGenerator((second, first)),
            critic=PolicyCritic(),
            oracle=oracle,
            memory=InMemoryRepairMemory(),
            budget=Budget(max_rounds=2, max_candidates=1, max_validations=1, batch_size=1),
        )
        result = await orchestrator.repair(make_task(), ValidationPlan())
        self.assertEqual(1, len(result.all_candidates))
        self.assertEqual(
            min(first.candidate_id, second.candidate_id), result.all_candidates[0].candidate_id
        )

    async def test_run_identity_separates_invocations_from_deterministic_inputs(self) -> None:
        baseline_stage = StageResult(
            stage="baseline.poc",
            verdict=StageVerdict.PASS,
            reason_code="baseline_vulnerability_reproduced",
            security_outcome=SecurityOutcome.VULNERABLE,
            artifacts=("evidence:baseline",),
        )

        async def execute(candidate: PatchCandidate):
            return await RepairOrchestrator(
                localizer=StaticLocalizer((make_location(),)),
                generator=StaticGenerator((candidate,)),
                critic=PolicyCritic(),
                oracle=FakeOracle({}, baseline_stages=(baseline_stage,)),
                memory=InMemoryRepairMemory(),
                budget=Budget(
                    max_rounds=1,
                    max_candidates=1,
                    max_validations=1,
                    batch_size=1,
                ),
            ).repair(make_task(), ValidationPlan())

        first_candidate = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        changed_candidate = PatchCandidate(task_id=make_task().task_id, diff=LARGE_DIFF)
        first = await execute(first_candidate)
        repeated = await execute(first_candidate)
        changed = await execute(changed_candidate)

        self.assertNotEqual(first.run_id, repeated.run_id)
        self.assertEqual(first.input_fingerprint, repeated.input_fingerprint)
        self.assertRegex(first.input_fingerprint, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first.input_fingerprint, changed.input_fingerprint)
        self.assertEqual((baseline_stage,), first.baseline.stages)

    async def test_verified_result_is_selected_before_noncritical_memory_write(self) -> None:
        candidate = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=StaticGenerator((candidate,)),
            critic=PolicyCritic(),
            oracle=FakeOracle({candidate.candidate_id: OverallVerdict.VERIFIED_FIX}),
            memory=BlockingMemory(),
            budget=Budget(max_elapsed_seconds=0.5),
        )

        started = time.monotonic()
        result = await orchestrator.repair(make_task(), ValidationPlan())

        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(candidate.candidate_id, result.chosen.candidate_id)

    async def test_wall_time_deadline_cancels_slow_baseline(self) -> None:
        candidate = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=StaticGenerator((candidate,)),
            critic=PolicyCritic(),
            oracle=SlowBaselineOracle({}),
            memory=InMemoryRepairMemory(),
            budget=Budget(max_elapsed_seconds=0.02),
        )

        started = time.monotonic()
        result = await orchestrator.repair(make_task(), ValidationPlan())

        self.assertLess(time.monotonic() - started, 0.5)
        self.assertIsNone(result.baseline)
        self.assertIsNone(result.chosen)
        self.assertIn("budget_exhausted", {event.event for event in result.trace})

    async def test_completed_verified_result_survives_later_batch_timeout(self) -> None:
        candidates = sorted(
            (
                PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF),
                PatchCandidate(task_id=make_task().task_id, diff=LARGE_DIFF),
            ),
            key=lambda candidate: candidate.candidate_id,
        )
        verified, slow = candidates
        oracle = SlowCandidateOracle(
            {verified.candidate_id: OverallVerdict.VERIFIED_FIX},
            slow_candidate_id=slow.candidate_id,
        )
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=StaticGenerator(tuple(candidates)),
            critic=PolicyCritic(),
            oracle=oracle,
            memory=InMemoryRepairMemory(),
            budget=Budget(
                max_rounds=1,
                max_candidates=2,
                max_validations=2,
                max_elapsed_seconds=0.5,
                batch_size=2,
            ),
        )

        result = await orchestrator.repair(make_task(), ValidationPlan())

        self.assertEqual(verified.candidate_id, result.chosen.candidate_id)
        self.assertEqual(
            (verified.candidate_id,), tuple(item.candidate_id for item in result.validations)
        )
        self.assertIn("budget_exhausted", {event.event for event in result.trace})

    async def test_model_call_and_cost_budgets_are_reserved_before_generation(self) -> None:
        candidate = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        generator = AccountingGenerator(candidate)
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=generator,
            critic=PolicyCritic(),
            oracle=FakeOracle({}),
            memory=InMemoryRepairMemory(),
            budget=Budget(
                max_rounds=3,
                max_candidates=3,
                max_validations=3,
                max_model_calls=1,
                max_cost_usd=0.01,
            ),
        )

        result = await orchestrator.repair(make_task(), ValidationPlan())

        self.assertEqual(1, generator.usage.calls)
        self.assertEqual(0.01, generator.usage.cost_usd)
        self.assertEqual(1, result.cost.model_calls)
        self.assertEqual(0.01, result.cost.cost_usd)
        self.assertEqual([(1, 0.01)], generator.reservations)

    async def test_shared_generator_usage_is_accounted_per_invocation(self) -> None:
        candidate = PatchCandidate(task_id=make_task().task_id, diff=SMALL_DIFF)
        generator = AccountingGenerator(candidate)
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=generator,
            critic=PolicyCritic(),
            oracle=FakeOracle({}),
            memory=InMemoryRepairMemory(),
            budget=Budget(
                max_rounds=1,
                max_candidates=1,
                max_validations=1,
                max_model_calls=1,
                max_cost_usd=0.01,
            ),
        )

        first = await orchestrator.repair(make_task(), ValidationPlan())
        second = await orchestrator.repair(make_task(), ValidationPlan())

        self.assertEqual(2, generator.usage.calls)
        self.assertEqual(1, first.cost.model_calls)
        self.assertEqual(1, second.cost.model_calls)
        self.assertEqual(0.01, first.cost.cost_usd)
        self.assertEqual(0.01, second.cost.cost_usd)
        self.assertEqual([(1, 0.01), (1, 0.01)], generator.reservations)

    async def test_persistence_is_bounded_by_the_wall_time_budget(self) -> None:
        orchestrator = RepairOrchestrator(
            localizer=StaticLocalizer((make_location(),)),
            generator=StaticGenerator(()),
            critic=PolicyCritic(),
            oracle=FakeOracle({}),
            memory=InMemoryRepairMemory(),
            store=SlowStore(),
            budget=Budget(max_elapsed_seconds=0.1),
        )

        started = time.monotonic()
        with self.assertRaises(BudgetDeadlineExceeded):
            await orchestrator.repair(make_task(), ValidationPlan())
        self.assertLess(time.monotonic() - started, 0.5)


if __name__ == "__main__":
    unittest.main()
