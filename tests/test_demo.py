from __future__ import annotations

import asyncio
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnrepair.adapters import InMemoryRepairMemory, PolicyCritic, StaticGenerator, StaticLocalizer
from vulnrepair.contracts import Budget, OverallVerdict
from vulnrepair.demo import GOOD_DIFF, demo_scenario
from vulnrepair.oracle import VerificationOracle
from vulnrepair.orchestrator import RepairOrchestrator
from vulnrepair.runners import LocalCommandRunner


class DemoIntegrationTests(unittest.TestCase):
    def test_good_patch_is_the_only_verified_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, demo_scenario(Path(temporary)) as scenario:
            budget = Budget(
                max_rounds=1,
                max_candidates=4,
                max_validations=4,
                max_elapsed_seconds=120,
                batch_size=4,
            )
            orchestrator = RepairOrchestrator(
                localizer=StaticLocalizer((scenario.location,)),
                generator=StaticGenerator(scenario.candidates),
                critic=PolicyCritic(),
                oracle=VerificationOracle(LocalCommandRunner(allow_unsafe=True)),
                memory=InMemoryRepairMemory(),
                budget=budget,
            )
            result = asyncio.run(orchestrator.repair(scenario.task, scenario.plan))
            self.assertIsNotNone(result.chosen)
            self.assertEqual(GOOD_DIFF, result.chosen.diff)
            self.assertEqual(
                [
                    OverallVerdict.VERIFIED_FIX,
                    OverallVerdict.REJECTED,
                    OverallVerdict.REJECTED,
                    OverallVerdict.REJECTED,
                ],
                [validation.overall for validation in result.validations],
            )
            status = subprocess.run(
                ("git", "status", "--porcelain"),
                cwd=scenario.repo,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual("", status.stdout)


if __name__ == "__main__":
    unittest.main()
