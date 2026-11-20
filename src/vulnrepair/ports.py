"""Async component boundaries for the generate-and-verify framework."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from .contracts import (
    BaselineResult,
    CodeLocation,
    CommandResult,
    CommandSpec,
    CritiqueResult,
    FailureRecord,
    LocalizationResult,
    PatchCandidate,
    RepairResult,
    ValidationPlan,
    ValidationResult,
    VulnTask,
)


@runtime_checkable
class LocalizerProtocol(Protocol):
    async def localize(self, task: VulnTask, *, failure_context: str | None = None) -> LocalizationResult: ...


@runtime_checkable
class GeneratorProtocol(Protocol):
    async def generate(
        self,
        task: VulnTask,
        locations: tuple[CodeLocation, ...],
        failures: tuple[FailureRecord, ...],
        limit: int,
        max_cost_usd: float,
    ) -> tuple[PatchCandidate, ...]: ...


@runtime_checkable
class CriticProtocol(Protocol):
    async def critique(self, candidate: PatchCandidate, task: VulnTask) -> CritiqueResult: ...


@runtime_checkable
class OracleProtocol(Protocol):
    async def prepare_baseline(self, task: VulnTask, plan: ValidationPlan) -> BaselineResult: ...

    async def validate(
        self,
        candidate: PatchCandidate,
        task: VulnTask,
        plan: ValidationPlan,
        baseline: BaselineResult,
    ) -> ValidationResult: ...


@runtime_checkable
class MemoryProtocol(Protocol):
    async def failures(self, task_id: str) -> tuple[FailureRecord, ...]: ...

    async def remember(
        self,
        task: VulnTask,
        candidate: PatchCandidate,
        validation: ValidationResult,
    ) -> None: ...


@runtime_checkable
class CommandRunnerProtocol(Protocol):
    async def run(self, spec: CommandSpec, workspace: Path) -> CommandResult: ...


@runtime_checkable
class RunStoreProtocol(Protocol):
    async def save(
        self,
        result: RepairResult,
        *,
        deadline: float | None = None,
    ) -> RepairResult: ...

    async def load(self, run_dir: Path) -> RepairResult: ...
