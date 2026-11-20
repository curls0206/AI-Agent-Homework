from __future__ import annotations

import inspect
import unittest
from pathlib import Path

from vulnrepair.contracts import (
    BaselineResult,
    CodeLocation,
    CommandResult,
    CommandSpec,
    FailureRecord,
    PatchCandidate,
    RepairResult,
    ValidationPlan,
    ValidationResult,
    VulnTask,
)
from vulnrepair.ports import (
    CommandRunnerProtocol,
    CriticProtocol,
    GeneratorProtocol,
    LocalizerProtocol,
    MemoryProtocol,
    OracleProtocol,
    RunStoreProtocol,
)


class CompleteAdapter:
    async def localize(self, task: VulnTask): ...
    async def generate(
        self,
        task: VulnTask,
        locations: tuple[CodeLocation, ...],
        failures: tuple[FailureRecord, ...],
        limit: int,
        max_cost_usd: float,
    ): ...
    async def critique(self, candidate: PatchCandidate, task: VulnTask): ...
    async def prepare_baseline(self, task: VulnTask, plan: ValidationPlan): ...
    async def validate(
        self,
        candidate: PatchCandidate,
        task: VulnTask,
        plan: ValidationPlan,
        baseline: BaselineResult,
    ): ...
    async def failures(self, task_id: str): ...
    async def remember(
        self, task: VulnTask, candidate: PatchCandidate, validation: ValidationResult
    ): ...
    async def run(self, spec: CommandSpec, workspace: Path) -> CommandResult: ...
    async def save(self, result: RepairResult) -> RepairResult: ...
    async def load(self, run_dir: Path) -> RepairResult: ...


class ProtocolTests(unittest.TestCase):
    def test_protocols_are_runtime_checkable(self) -> None:
        adapter = CompleteAdapter()
        protocols = (
            LocalizerProtocol,
            GeneratorProtocol,
            CriticProtocol,
            OracleProtocol,
            MemoryProtocol,
            CommandRunnerProtocol,
            RunStoreProtocol,
        )
        for protocol in protocols:
            with self.subTest(protocol=protocol.__name__):
                self.assertIsInstance(adapter, protocol)

    def test_declared_port_methods_are_async(self) -> None:
        methods = (
            CompleteAdapter.localize,
            CompleteAdapter.generate,
            CompleteAdapter.critique,
            CompleteAdapter.prepare_baseline,
            CompleteAdapter.validate,
            CompleteAdapter.failures,
            CompleteAdapter.remember,
            CompleteAdapter.run,
            CompleteAdapter.save,
            CompleteAdapter.load,
        )
        self.assertTrue(all(inspect.iscoroutinefunction(method) for method in methods))


if __name__ == "__main__":
    unittest.main()
