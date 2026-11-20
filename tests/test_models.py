from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnrepair.contracts import CodeLocation, FailureRecord, OverallVerdict, VulnTask
from vulnrepair.demo import demo_scenario
from vulnrepair.models import (
    GitSnapshotContextProvider,
    MappingContextProvider,
    ModelPoolGenerator,
    ModelResponse,
    build_patch_prompt,
)

DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-return value
+return escape(value)
"""


def task() -> VulnTask:
    return VulnTask(
        task_id="task-model",
        cve_id="CVE-2099-1",
        cwe_id="CWE-79",
        description="HTML injection",
        repo_path="repo",
        language="python",
        affected_versions="< 2",
    )


def location() -> CodeLocation:
    return CodeLocation(
        file_path="app.py",
        function_name="render",
        start_line=1,
        end_line=1,
        confidence=1.0,
        rationale="known fixture",
    )


@dataclass
class FakeClient:
    model_id: str
    text: str
    cost_usd: float = 0.01

    async def complete(
        self,
        prompt: str,
        *,
        temperature: float,
        max_tokens: int,
        max_cost_usd: float,
    ) -> ModelResponse:
        self.last_prompt = prompt
        self.last_cost_limit = max_cost_usd
        return ModelResponse(
            text=self.text,
            model_id=self.model_id,
            prompt_tokens=10,
            completion_tokens=5,
            cost_usd=self.cost_usd,
        )


class ModelTests(unittest.IsolatedAsyncioTestCase):
    async def test_git_context_uses_committed_snapshot_not_dirty_worktree(self) -> None:
        with TemporaryDirectory() as temporary, demo_scenario(Path(temporary)) as demo:
            (demo.repo / "app.py").write_text("DIRTY SECRET\n", encoding="utf-8")
            context = await GitSnapshotContextProvider().context(demo.task, demo.location)

        self.assertIn('return f"<p>{name}</p>"', context)
        self.assertNotIn("DIRTY SECRET", context)

    async def test_git_context_rejects_workspace_escape(self) -> None:
        provider = GitSnapshotContextProvider()
        unsafe = CodeLocation(
            file_path="../secret.txt",
            function_name=None,
            start_line=1,
            end_line=1,
            confidence=1.0,
            rationale="fixture",
        )
        with self.assertRaises(ValueError):
            await provider.context(task(), unsafe)

    async def test_pool_deduplicates_and_accounts_usage(self) -> None:
        first = FakeClient("model-a", DIFF)
        second = FakeClient("model-b", f"```diff\n{DIFF}```")
        provider = MappingContextProvider({("app.py", 1, 1): "return value"})
        generator = ModelPoolGenerator((second, first), provider)
        candidates = await generator.generate(task(), (location(),), (), 2, 0.02)
        self.assertEqual(1, len(candidates))
        self.assertEqual(2, generator.usage.calls)
        self.assertEqual(20, generator.usage.prompt_tokens)
        self.assertEqual(0.02, generator.usage.cost_usd)

    async def test_provider_failure_does_not_cancel_pool(self) -> None:
        @dataclass
        class BrokenClient:
            model_id: str = "broken"

            async def complete(
                self,
                prompt: str,
                *,
                temperature: float,
                max_tokens: int,
                max_cost_usd: float,
            ) -> ModelResponse:
                raise RuntimeError("offline")

        good = FakeClient("good", DIFF)
        provider = MappingContextProvider({("app.py", 1, 1): "return value"})
        generator = ModelPoolGenerator((BrokenClient(), good), provider)
        self.assertEqual(1, len(await generator.generate(task(), (location(),), (), 2, 0.02)))
        self.assertEqual(2, generator.usage.calls)
        self.assertEqual(1, len(generator.last_errors))
        self.assertIn("broken sample 1: RuntimeError", generator.last_errors[0])

    async def test_generation_limit_caps_model_calls_before_scheduling(self) -> None:
        first = FakeClient("model-a", DIFF)
        second = FakeClient("model-b", DIFF)
        provider = MappingContextProvider({("app.py", 1, 1): "return value"})
        generator = ModelPoolGenerator((first, second), provider, samples_per_model=3)
        candidates = await generator.generate(task(), (location(),), (), 1, 0.01)
        self.assertEqual(1, len(candidates))
        self.assertEqual(1, generator.usage.calls)

    async def test_cost_budget_is_reserved_before_concurrent_calls(self) -> None:
        first = FakeClient("model-a", DIFF)
        second = FakeClient("model-b", DIFF)
        provider = MappingContextProvider({("app.py", 1, 1): "return value"})
        generator = ModelPoolGenerator((first, second), provider)

        await generator.generate(task(), (location(),), (), 2, 0.02)

        self.assertAlmostEqual(0.01, first.last_cost_limit)
        self.assertAlmostEqual(0.01, second.last_cost_limit)
        self.assertLessEqual(generator.usage.cost_usd, 0.02)

    async def test_provider_cost_contract_violation_discards_candidates(self) -> None:
        client = FakeClient("over-budget", DIFF, cost_usd=0.02)
        provider = MappingContextProvider({("app.py", 1, 1): "return value"})
        generator = ModelPoolGenerator((client,), provider)

        candidates = await generator.generate(task(), (location(),), (), 1, 0.01)

        self.assertEqual((), candidates)
        self.assertEqual(1, generator.usage.calls)
        self.assertEqual(1, generator.usage.budget_violations)
        self.assertEqual(0.02, generator.usage.cost_usd)

    def test_prompt_contains_failure_feedback_but_no_ground_truth_field(self) -> None:
        failure = FailureRecord(
            task_id="task-model",
            candidate_id="a" * 64,
            overall=OverallVerdict.REJECTED,
            reason="exploit persisted",
        )
        prompt = build_patch_prompt(task(), location(), "return value", (failure,))
        self.assertIn("exploit persisted", prompt)
        self.assertNotIn("fixing_commit", prompt)


if __name__ == "__main__":
    unittest.main()
