"""Deterministic adapters used by offline runs and tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .contracts import (
    CodeLocation,
    CritiqueResult,
    CritiqueVerdict,
    FailureRecord,
    LocalizationResult,
    OverallVerdict,
    PatchCandidate,
    ValidationResult,
    VulnTask,
)
from .patches import PatchPolicy, PatchPolicyError


@dataclass(frozen=True, slots=True)
class StaticLocalizer:
    """Return caller-provided locations without consulting a model."""

    locations: tuple[CodeLocation, ...]

    async def localize(self, task: VulnTask, *, failure_context: str | None = None) -> LocalizationResult:
        ordered = tuple(
            sorted(
                self.locations,
                key=lambda item: (-item.confidence, item.file_path, item.start_line, item.end_line),
            )
        )
        return LocalizationResult(task_id=task.task_id, candidates=ordered)


@dataclass(frozen=True, slots=True)
class StaticGenerator:
    """Expose a fixed candidate set through the generator port."""

    candidates: tuple[PatchCandidate, ...]

    async def generate(
        self,
        task: VulnTask,
        locations: tuple[CodeLocation, ...],
        failures: tuple[FailureRecord, ...],
        limit: int,
        max_cost_usd: float,
    ) -> tuple[PatchCandidate, ...]:
        del locations, failures, max_cost_usd
        if limit <= 0:
            return ()
        return tuple(
            sorted(
                (candidate for candidate in self.candidates if candidate.task_id == task.task_id),
                key=lambda candidate: candidate.candidate_id,
            )[:limit]
        )


@dataclass(frozen=True, slots=True)
class PolicyCritic:
    """A fail-fast deterministic critic for unsafe or malformed diffs.

    This adapter deliberately makes no semantic claim about whether the patch
    fixes the vulnerability.  Uncertain candidates pass to the Oracle.
    """

    policy: PatchPolicy = PatchPolicy()

    async def critique(self, candidate: PatchCandidate, task: VulnTask) -> CritiqueResult:
        try:
            self.policy.inspect(candidate, task.task_id)
        except PatchPolicyError as exc:
            return CritiqueResult(
                candidate_id=candidate.candidate_id,
                verdict=CritiqueVerdict.REJECT,
                issues=(f"{exc.reason_code}: {exc}",),
            )
        return CritiqueResult(
            candidate_id=candidate.candidate_id,
            verdict=CritiqueVerdict.PASS,
        )


@dataclass(slots=True)
class InMemoryRepairMemory:
    """Task-local failure memory with stable insertion order."""

    _records: dict[str, list[FailureRecord]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def failures(self, task_id: str) -> tuple[FailureRecord, ...]:
        async with self._lock:
            return tuple(self._records.get(task_id, ()))

    async def remember(
        self,
        task: VulnTask,
        candidate: PatchCandidate,
        validation: ValidationResult,
    ) -> None:
        if validation.overall is OverallVerdict.VERIFIED_FIX:
            return
        # Extract PoC stdout so the generator can see why the exploit still fired.
        poc_stage = next(
            (s for s in validation.stages if s.stage.endswith(".poc")), None
        )
        poc_detail: str | None = None
        if poc_stage and poc_stage.command_result and poc_stage.command_result.stdout:
            poc_detail = poc_stage.command_result.stdout.strip()[:400]
        record = FailureRecord(
            task_id=task.task_id,
            candidate_id=candidate.candidate_id,
            overall=validation.overall,
            reason=validation.summary or validation.overall.value,
            poc_detail=poc_detail,
        )
        async with self._lock:
            records = self._records.setdefault(task.task_id, [])
            if all(existing.candidate_id != candidate.candidate_id for existing in records):
                records.append(record)


__all__ = [
    "InMemoryRepairMemory",
    "PolicyCritic",
    "StaticGenerator",
    "StaticLocalizer",
]
