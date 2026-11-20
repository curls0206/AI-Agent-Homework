from __future__ import annotations

import unittest

from vulnrepair.adapters import InMemoryRepairMemory, PolicyCritic, StaticGenerator, StaticLocalizer
from vulnrepair.contracts import (
    CodeLocation,
    CritiqueVerdict,
    OverallVerdict,
    PatchCandidate,
    ValidationResult,
    VulnTask,
)

VALID_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-old
+new
"""


def task() -> VulnTask:
    return VulnTask(
        task_id="task-1",
        cve_id=None,
        cwe_id="CWE-79",
        description="HTML injection",
        repo_path="repo",
        language="python",
        affected_versions="1.0",
    )


def location() -> CodeLocation:
    return CodeLocation(
        file_path="app.py",
        function_name="render",
        start_line=1,
        end_line=1,
        confidence=0.9,
        rationale="fixture",
    )


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_static_components_are_stable(self) -> None:
        candidate = PatchCandidate(task_id="task-1", diff=VALID_DIFF, target_location=location())
        localized = await StaticLocalizer((location(),)).localize(task())
        generated = await StaticGenerator((candidate,)).generate(
            task(), localized.candidates, (), 1, 0.0
        )
        self.assertEqual((candidate,), generated)

    async def test_policy_critic_rejects_validation_assets(self) -> None:
        unsafe = PatchCandidate(
            task_id="task-1",
            diff=VALID_DIFF.replace("app.py", "tests/test_app.py"),
        )
        critique = await PolicyCritic().critique(unsafe, task())
        self.assertIs(critique.verdict, CritiqueVerdict.REJECT)
        self.assertIn("validation_asset", critique.issues[0])

    async def test_memory_deduplicates_failures(self) -> None:
        memory = InMemoryRepairMemory()
        candidate = PatchCandidate(task_id="task-1", diff=VALID_DIFF)
        validation = ValidationResult(
            candidate_id=candidate.candidate_id,
            stages=(),
            overall=OverallVerdict.REJECTED,
            summary="regression",
        )
        await memory.remember(task(), candidate, validation)
        await memory.remember(task(), candidate, validation)
        failures = await memory.failures("task-1")
        self.assertEqual(1, len(failures))
        self.assertEqual("regression", failures[0].reason)


if __name__ == "__main__":
    unittest.main()
