"""Deterministic, budget-aware generate-and-verify orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import partial
from typing import TypeVar

from .contracts import (
    BaselineResult,
    Budget,
    CodeLocation,
    CostSummary,
    CritiqueVerdict,
    OverallVerdict,
    PatchCandidate,
    RepairResult,
    TraceEvent,
    ValidationPlan,
    ValidationResult,
    VulnTask,
)
from .patches import PatchPolicy, PatchPolicyError
from .ports import (
    CriticProtocol,
    GeneratorProtocol,
    LocalizerProtocol,
    MemoryProtocol,
    OracleProtocol,
    RunStoreProtocol,
)

T = TypeVar("T")


class BudgetDeadlineExceeded(TimeoutError):
    """The orchestration wall-clock deadline was reached."""


async def _before_deadline(factory: Callable[[], Awaitable[T]], deadline: float) -> T:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BudgetDeadlineExceeded("wall-time budget reached")
    timeout_context = asyncio.timeout(remaining)
    try:
        async with timeout_context:
            return await factory()
    except TimeoutError as exc:
        if timeout_context.expired():
            raise BudgetDeadlineExceeded("wall-time budget reached") from exc
        raise


@dataclass(slots=True)
class RepairOrchestrator:
    localizer: LocalizerProtocol
    generator: GeneratorProtocol
    critic: CriticProtocol
    oracle: OracleProtocol
    memory: MemoryProtocol
    budget: Budget
    store: RunStoreProtocol | None = None
    patch_policy: PatchPolicy = PatchPolicy()

    async def repair(self, task: VulnTask, plan: ValidationPlan) -> RepairResult:
        started = time.monotonic()
        final_deadline = started + self.budget.max_elapsed_seconds
        persistence_reserve = (
            min(1.0, self.budget.max_elapsed_seconds * 0.1) if self.store is not None else 0.0
        )
        deadline = final_deadline - persistence_reserve
        run_id = uuid.uuid4().hex
        trace: list[TraceEvent] = []
        candidates: dict[str, PatchCandidate] = {}
        validations: list[ValidationResult] = []
        chosen: PatchCandidate | None = None
        baseline: BaselineResult | None = None
        locations: tuple[CodeLocation, ...] = ()
        rounds = 0
        deadline_hit = False
        usage_at_start = getattr(self.generator, "usage", None)
        initial_model_calls = int(getattr(usage_at_start, "calls", 0))
        initial_prompt_tokens = int(getattr(usage_at_start, "prompt_tokens", 0))
        initial_completion_tokens = int(getattr(usage_at_start, "completion_tokens", 0))
        initial_cost_usd = float(getattr(usage_at_start, "cost_usd", 0.0))
        initial_budget_violations = int(getattr(usage_at_start, "budget_violations", 0))

        def emit(
            event: str, message: str = "", candidate_id: str | None = None, **attributes: str
        ) -> None:
            trace.append(
                TraceEvent(
                    sequence=len(trace),
                    event=event,
                    task_id=task.task_id,
                    candidate_id=candidate_id,
                    message=message,
                    attributes=tuple(
                        sorted((key, str(value)) for key, value in attributes.items())
                    ),
                )
            )

        emit("run_started", run_id=run_id)
        try:
            baseline = await _before_deadline(
                lambda: self.oracle.prepare_baseline(task, plan), deadline
            )
        except BudgetDeadlineExceeded:
            deadline_hit = True
            emit("budget_exhausted", "wall-time budget reached during baseline")
        if baseline is not None:
            emit("baseline_ready" if baseline.usable else "baseline_unusable", baseline.summary)

        if baseline is not None and baseline.usable and not deadline_hit:
            try:
                localization = await _before_deadline(
                    lambda: self.localizer.localize(task), deadline
                )
            except BudgetDeadlineExceeded:
                deadline_hit = True
                emit("budget_exhausted", "wall-time budget reached during localization")
            else:
                if localization.task_id != task.task_id:
                    raise ValueError("localizer returned a result for a different task")
                locations = tuple(
                    sorted(
                        localization.candidates,
                        key=lambda item: (
                            -item.confidence,
                            item.file_path,
                            item.start_line,
                            item.end_line,
                        ),
                    )
                )
                emit("localized", locations=str(len(locations)))

            for round_number in range(1, self.budget.max_rounds + 1) if not deadline_hit else ():
                if time.monotonic() >= deadline:
                    emit("budget_exhausted", "wall-time budget reached")
                    break
                if len(candidates) >= self.budget.max_candidates:
                    emit("budget_exhausted", "candidate budget reached")
                    break
                if len(validations) >= self.budget.max_validations:
                    emit("budget_exhausted", "validation budget reached")
                    break

                rounds = round_number
                remaining_candidates = self.budget.max_candidates - len(candidates)
                usage = getattr(self.generator, "usage", None)
                used_calls = int(getattr(usage, "calls", 0)) - initial_model_calls
                used_cost = float(getattr(usage, "cost_usd", 0.0)) - initial_cost_usd
                remaining_calls = self.budget.max_model_calls - used_calls
                remaining_cost = self.budget.max_cost_usd - used_cost
                if usage is not None and remaining_calls <= 0:
                    emit("budget_exhausted", "model-call budget reached")
                    break
                if usage is not None and remaining_cost <= 0:
                    emit("budget_exhausted", "model-cost budget reached")
                    break
                generation_limit = (
                    min(remaining_candidates, remaining_calls)
                    if usage is not None
                    else remaining_candidates
                )
                try:
                    failures = await _before_deadline(
                        lambda: self.memory.failures(task.task_id), deadline
                    )
                except BudgetDeadlineExceeded:
                    deadline_hit = True
                    emit("budget_exhausted", "wall-time budget reached during generation")
                    break

                # PoC-feedback-driven re-localization: on every round after the
                # first, pass the latest PoC failure output back to the Localizer
                # so it can revise its location hypothesis.  This handles both
                # localization failures (wrong file) and generation failures
                # (right file, wrong fix) without CWE-specific rules.
                if round_number > 1 and failures:
                    poc_context = next(
                        (f.poc_detail for f in reversed(failures) if f.poc_detail),
                        None,
                    )
                    if poc_context:
                        _ctx = poc_context  # capture for lambda
                        try:
                            relock = await _before_deadline(
                                lambda: self.localizer.localize(task, failure_context=_ctx),
                                deadline,
                            )
                        except BudgetDeadlineExceeded:
                            deadline_hit = True
                            emit("budget_exhausted", "wall-time budget reached during re-localization")
                            break
                        if relock.task_id == task.task_id and relock.candidates:
                            locations = tuple(
                                sorted(
                                    relock.candidates,
                                    key=lambda item: (
                                        -item.confidence,
                                        item.file_path,
                                        item.start_line,
                                        item.end_line,
                                    ),
                                )
                            )
                            emit("relocalized", round=str(round_number), locations=str(len(locations)))

                try:
                    generated = await _before_deadline(
                        partial(
                            self.generator.generate,
                            task,
                            locations,
                            failures,
                            generation_limit,
                            max(0.0, remaining_cost),
                        ),
                        deadline,
                    )
                except BudgetDeadlineExceeded:
                    deadline_hit = True
                    emit("budget_exhausted", "wall-time budget reached during generation")
                    break
                provider_errors = tuple(getattr(self.generator, "last_errors", ()))
                if provider_errors:
                    emit(
                        "provider_errors",
                        " | ".join(provider_errors[:3]),
                        count=str(len(provider_errors)),
                    )
                usage = getattr(self.generator, "usage", None)
                if usage is not None and (
                    int(getattr(usage, "calls", 0)) - initial_model_calls
                    > self.budget.max_model_calls
                    or float(getattr(usage, "cost_usd", 0.0)) - initial_cost_usd
                    > self.budget.max_cost_usd + 1e-12
                    or int(getattr(usage, "budget_violations", 0)) > initial_budget_violations
                ):
                    emit(
                        "budget_violation",
                        "generator exceeded its reserved model budget; generated candidates discarded",
                    )
                    break
                ordered_new = [
                    candidate
                    for candidate in sorted(generated, key=lambda item: item.candidate_id)
                    if candidate.task_id == task.task_id
                    and candidate.candidate_id not in candidates
                ]
                ordered_new = ordered_new[:remaining_candidates]
                if not ordered_new:
                    emit("round_empty", round=str(round_number))
                    if provider_errors:
                        # A transient provider failure (bad JSON, timeout) must not end the run
                        # while rounds and model-call budget remain; the round limit bounds retries.
                        continue
                    break
                for candidate in ordered_new:
                    candidates[candidate.candidate_id] = candidate
                emit("candidates_generated", round=str(round_number), count=str(len(ordered_new)))

                accepted: list[PatchCandidate] = []
                for candidate in ordered_new:
                    try:
                        critique = await _before_deadline(
                            partial(self.critic.critique, candidate, task),
                            deadline,
                        )
                    except BudgetDeadlineExceeded:
                        deadline_hit = True
                        emit("budget_exhausted", "wall-time budget reached during critique")
                        break
                    if critique.candidate_id != candidate.candidate_id:
                        raise ValueError("critic returned a result for a different candidate")
                    if critique.verdict is CritiqueVerdict.PASS:
                        accepted.append(candidate)
                        emit("critic_pass", candidate_id=candidate.candidate_id)
                    else:
                        emit(
                            "critic_reject",
                            "; ".join(critique.issues),
                            candidate_id=candidate.candidate_id,
                        )
                if deadline_hit:
                    break

                remaining_validations = self.budget.max_validations - len(validations)
                accepted = accepted[:remaining_validations]
                for offset in range(0, len(accepted), self.budget.batch_size):
                    batch = accepted[offset : offset + self.budget.batch_size]
                    batch_results: list[tuple[PatchCandidate, ValidationResult]] = []
                    for candidate in batch:
                        try:
                            validation = await _before_deadline(
                                partial(self.oracle.validate, candidate, task, plan, baseline),
                                deadline,
                            )
                        except BudgetDeadlineExceeded:
                            deadline_hit = True
                            emit(
                                "budget_exhausted",
                                "wall-time budget reached during validation",
                                candidate_id=candidate.candidate_id,
                            )
                            break
                        if validation.candidate_id != candidate.candidate_id:
                            raise ValueError("Oracle returned a result for a different candidate")
                        validations.append(validation)
                        batch_results.append((candidate, validation))
                        emit(
                            "candidate_validated",
                            validation.summary,
                            candidate_id=candidate.candidate_id,
                            verdict=validation.overall.value,
                        )

                    verified = [
                        candidate
                        for candidate, result in batch_results
                        if result.overall is OverallVerdict.VERIFIED_FIX
                    ]
                    if verified:
                        chosen = min(
                            verified, key=lambda item: self._candidate_rank(item, task.task_id)
                        )
                        emit("verified_fix_selected", candidate_id=chosen.candidate_id)
                        break
                    if deadline_hit:
                        break
                    for candidate, validation in batch_results:
                        try:
                            await _before_deadline(
                                partial(self.memory.remember, task, candidate, validation),
                                deadline,
                            )
                        except BudgetDeadlineExceeded:
                            deadline_hit = True
                            emit(
                                "budget_exhausted",
                                "wall-time budget reached while recording memory",
                                candidate_id=candidate.candidate_id,
                            )
                            break
                    if deadline_hit:
                        break
                if chosen is not None or deadline_hit:
                    break

        elapsed = time.monotonic() - started
        usage = getattr(self.generator, "usage", None)
        persistence_charge = 0.0
        if self.store is not None:
            persistence_charge = min(
                persistence_reserve,
                max(1e-12, self.budget.max_elapsed_seconds - elapsed),
            )
        cost = CostSummary(
            rounds=rounds,
            candidates_seen=len(candidates),
            candidates_validated=len(validations),
            elapsed_seconds=elapsed + persistence_charge,
            persistence_seconds=persistence_charge,
            model_calls=int(getattr(usage, "calls", 0)) - initial_model_calls,
            prompt_tokens=int(getattr(usage, "prompt_tokens", 0)) - initial_prompt_tokens,
            completion_tokens=int(getattr(usage, "completion_tokens", 0))
            - initial_completion_tokens,
            cost_usd=float(getattr(usage, "cost_usd", 0.0)) - initial_cost_usd,
        )
        input_fingerprint = _derive_input_fingerprint(
            task,
            plan,
            self.budget,
            locations,
            tuple(candidates[key] for key in sorted(candidates)),
            baseline,
        )
        emit(
            "run_finished",
            chosen=candidate_or_none(chosen),
            elapsed=f"{elapsed:.6f}",
            input_fingerprint=input_fingerprint,
        )
        repair_result = RepairResult(
            run_id=run_id,
            input_fingerprint=input_fingerprint,
            task_id=task.task_id,
            baseline=baseline,
            chosen=chosen,
            all_candidates=tuple(candidates[key] for key in sorted(candidates)),
            validations=tuple(validations),
            attempts=rounds,
            cost=cost,
            trace=tuple(trace),
            budget=self.budget,
        )
        if self.store is not None:
            repair_result = await _before_deadline(
                partial(self.store.save, repair_result, deadline=final_deadline),
                final_deadline,
            )
        return repair_result

    def _candidate_rank(self, candidate: PatchCandidate, task_id: str) -> tuple[int, int, str]:
        try:
            inspection = self.patch_policy.inspect(candidate, task_id)
        except PatchPolicyError:
            return (2**31 - 1, 2**31 - 1, candidate.candidate_id)
        return (
            inspection.changed_file_count,
            inspection.changed_lines,
            candidate.candidate_id,
        )


def candidate_or_none(candidate: PatchCandidate | None) -> str:
    return candidate.candidate_id if candidate is not None else "none"


def _derive_input_fingerprint(
    task: VulnTask,
    plan: ValidationPlan,
    budget: Budget,
    locations: tuple[CodeLocation, ...],
    candidates: tuple[PatchCandidate, ...],
    baseline: BaselineResult | None,
) -> str:
    payload = {
        "task": task.to_dict(),
        "plan": plan.to_dict(),
        "budget": budget.to_dict(),
        "locations": [location.to_dict() for location in locations],
        "candidates": [candidate.to_dict() for candidate in candidates],
        "snapshot": baseline.snapshot.to_dict()
        if baseline is not None and baseline.snapshot is not None
        else None,
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = ["BudgetDeadlineExceeded", "RepairOrchestrator"]
