from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

from vulnrepair.codex import (
    CodexBudgetExceeded,
    CodexCliClient,
    CodexCliError,
    CodexInvocation,
    CodexProcessResult,
    CodexTimeoutError,
    _codex_environment,
    _finish_process_cleanup,
    _run_codex_process,
    build_codex_argv,
)
from vulnrepair.models import ModelClientProtocol

DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-return value
+return escape(value)
"""


@dataclass
class RecordingRunner:
    response: str = DIFF
    returncode: int = 0
    stderr: str = ""
    calls: list[tuple[CodexInvocation, str]] = field(default_factory=list)

    async def __call__(self, invocation: CodexInvocation, prompt: str) -> CodexProcessResult:
        self.calls.append((invocation, prompt))
        if self.returncode == 0:
            invocation.output_path.write_text(self.response, encoding="utf-8")
        return CodexProcessResult(self.returncode, self.stderr)


class CodexClientTests(unittest.IsolatedAsyncioTestCase):
    def test_command_is_fixed_argv_with_prompt_on_stdin(self) -> None:
        output = Path.cwd().resolve() / "last-message.txt"
        argv = build_codex_argv(
            "codex.exe",
            model_id="gpt-5.3-codex",
            reasoning_effort="xhigh",
            output_path=output,
        )

        self.assertEqual("codex.exe", argv[0])
        self.assertEqual("exec", argv[1])
        self.assertEqual("gpt-5.3-codex", argv[argv.index("--model") + 1])
        self.assertEqual("read-only", argv[argv.index("--sandbox") + 1])
        self.assertIn("--ephemeral", argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--skip-git-repo-check", argv)
        self.assertEqual(str(output), argv[argv.index("--output-last-message") + 1])
        self.assertIn('model_reasoning_effort="xhigh"', argv)
        self.assertEqual("-", argv[-1])

    async def test_client_satisfies_protocol_and_reads_only_last_message(self) -> None:
        runner = RecordingRunner()
        client = CodexCliClient(
            model_id="gpt-5.5",
            executable=sys.executable,
            accounting_cost_usd=0.03,
            runner=runner,
        )
        self.assertIsInstance(client, ModelClientProtocol)

        response = await client.complete(
            "produce a patch",
            temperature=0.2,
            max_tokens=2_048,
            max_cost_usd=0.03,
        )

        self.assertEqual(DIFF, response.text)
        self.assertEqual("gpt-5.5", response.model_id)
        self.assertEqual(0.03, response.cost_usd)
        self.assertGreaterEqual(response.latency_seconds, 0)
        self.assertEqual("produce a patch", runner.calls[0][1])
        invocation = runner.calls[0][0]
        self.assertFalse(invocation.output_path.exists())
        self.assertEqual(invocation.cwd, invocation.output_path.parent)

    async def test_cost_is_rejected_before_runner_or_executable_lookup(self) -> None:
        runner = RecordingRunner()
        client = CodexCliClient(
            executable="definitely-missing-codex-executable",
            accounting_cost_usd=0.02,
            runner=runner,
        )

        with self.assertRaises(CodexBudgetExceeded):
            await client.complete(
                "patch",
                temperature=0.2,
                max_tokens=10,
                max_cost_usd=0.01,
            )
        self.assertEqual([], runner.calls)

    async def test_nonzero_exit_is_not_mistaken_for_a_model_response(self) -> None:
        client = CodexCliClient(
            executable=sys.executable,
            runner=RecordingRunner(returncode=2, stderr="authentication failed"),
        )

        with self.assertRaisesRegex(CodexCliError, "status 2"):
            await client.complete(
                "patch",
                temperature=0.2,
                max_tokens=10,
                max_cost_usd=1,
            )

    async def test_empty_and_oversized_responses_fail_closed(self) -> None:
        for response, limit in (("", 128), ("x" * 129, 128)):
            with self.subTest(response_size=len(response)):
                client = CodexCliClient(
                    executable=sys.executable,
                    max_output_bytes=limit,
                    runner=RecordingRunner(response=response),
                )
                with self.assertRaises(CodexCliError):
                    await client.complete(
                        "patch",
                        temperature=0.2,
                        max_tokens=10,
                        max_cost_usd=1,
                    )

    async def test_injected_runner_cancellation_propagates(self) -> None:
        started = asyncio.Event()
        cleaned = asyncio.Event()

        async def blocking_runner(invocation: CodexInvocation, prompt: str) -> CodexProcessResult:
            del invocation, prompt
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()

        client = CodexCliClient(executable=sys.executable, runner=blocking_runner)
        task = asyncio.create_task(
            client.complete(
                "patch",
                temperature=0.2,
                max_tokens=10,
                max_cost_usd=1,
            )
        )
        await started.wait()
        task.cancel()

        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(cleaned.is_set())

    async def test_default_runner_delivers_prompt_through_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "captured.txt"
            code = (
                "import pathlib,sys; "
                "pathlib.Path(sys.argv[1]).write_text(sys.stdin.read(), encoding='utf-8')"
            )
            invocation = CodexInvocation(
                argv=(sys.executable, "-c", code, str(output)),
                cwd=root,
                environment=dict(os.environ),
                output_path=output,
                timeout_seconds=5,
                max_stderr_bytes=1_024,
            )

            result = await _run_codex_process(invocation, "secret prompt\nsecond line")

            self.assertEqual(0, result.returncode)
            self.assertEqual("secret prompt\nsecond line", output.read_text(encoding="utf-8"))
            self.assertNotIn("secret prompt", invocation.argv)

    async def test_default_runner_times_out_and_returns_promptly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            invocation = CodexInvocation(
                argv=(sys.executable, "-c", "import time; time.sleep(30)"),
                cwd=root,
                environment=dict(os.environ),
                output_path=root / "unused.txt",
                timeout_seconds=0.05,
                max_stderr_bytes=1_024,
                termination_grace_seconds=0,
            )
            started = time.monotonic()

            with self.assertRaises(CodexTimeoutError):
                await _run_codex_process(invocation, "prompt")

            self.assertLess(time.monotonic() - started, 5)

    async def test_cleanup_is_shielded_and_cancels_pipe_tasks(self) -> None:
        class FakeProcess:
            pid = 12345
            returncode = None

        waiting = asyncio.create_task(asyncio.Event().wait())
        terminated = False

        async def fake_terminate(process: object, grace_seconds: float) -> None:
            nonlocal terminated
            del process, grace_seconds
            await asyncio.sleep(0)
            terminated = True

        with patch("vulnrepair.codex._terminate_process_tree", fake_terminate):
            await _finish_process_cleanup(FakeProcess(), (waiting,), 0)  # type: ignore[arg-type]

        self.assertTrue(terminated)
        self.assertTrue(waiting.cancelled())

    def test_environment_does_not_forward_ambient_api_secrets(self) -> None:
        with patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "do-not-forward", "CODEX_HOME": "C:/codex-home"},
            clear=False,
        ):
            environment = _codex_environment()

        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual("C:/codex-home", environment["CODEX_HOME"])

    def test_configuration_validation(self) -> None:
        for arguments in (
            {"model_id": ""},
            {"model_id": "bad\nmodel"},
            {"reasoning_effort": "maximum"},
            {"timeout_seconds": 0},
            {"accounting_cost_usd": -1},
            {"max_output_bytes": 0},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                CodexCliClient(**arguments)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
