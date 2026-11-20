from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from vulnrepair.cli import _make_generator, build_parser, load_scenario, main
from vulnrepair.contracts import SCHEMA_VERSION, Budget, CostSummary, RepairResult
from vulnrepair.demo import demo_scenario
from vulnrepair.models import ModelPoolGenerator


class CliTests(unittest.TestCase):
    def test_dashboard_command_starts_read_only_server(self) -> None:
        with mock.patch("vulnrepair.dashboard.serve_dashboard") as serve:
            code = main(
                (
                    "dashboard",
                    "--runs",
                    "audit-runs",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "9010",
                )
            )

        self.assertEqual(0, code)
        serve.assert_called_once_with(
            Path("audit-runs"),
            host="127.0.0.1",
            port=9010,
            allow_remote=False,
        )

    def test_codex_profiles_build_explicit_model_clients(self) -> None:
        parser = build_parser()
        scenario = mock.Mock(candidates=())
        spark = parser.parse_args(
            ("repair", "scenario.json", "--generator", "codex", "--codex-profile", "spark")
        )
        generator = _make_generator(spark, scenario)

        self.assertIsInstance(generator, ModelPoolGenerator)
        self.assertEqual(
            ("gpt-5.3-codex-spark",), tuple(client.model_id for client in generator.clients)
        )
        self.assertEqual("medium", generator.clients[0].reasoning_effort)

        pool = parser.parse_args(
            (
                "repair",
                "scenario.json",
                "--generator",
                "codex",
                "--codex-model",
                "gpt-5.5",
                "--codex-model",
                "gpt-5.3-codex-spark",
                "--codex-reasoning-effort",
                "xhigh",
            )
        )
        generator = _make_generator(pool, scenario)
        self.assertEqual(
            ("gpt-5.5", "gpt-5.3-codex-spark"),
            tuple(client.model_id for client in generator.clients),
        )
        self.assertTrue(all(client.reasoning_effort == "xhigh" for client in generator.clients))

    def test_codex_pool_rejects_duplicate_model_ids(self) -> None:
        arguments = build_parser().parse_args(
            (
                "repair",
                "scenario.json",
                "--generator",
                "codex",
                "--codex-model",
                "gpt-5.5",
                "--codex-model",
                "gpt-5.5",
            )
        )
        with self.assertRaisesRegex(ValueError, "unique"):
            _make_generator(arguments, mock.Mock(candidates=()))

    def test_demo_writes_auditable_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "runs"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(
                    (
                        "demo",
                        "--runner",
                        "local",
                        "--allow-unsafe-local-exec",
                        "--output",
                        str(output),
                    )
                )
            self.assertEqual(0, code)
            summary = json.loads(stdout.getvalue())
            run_dir = Path(summary["artifact_dir"])
            self.assertTrue((run_dir / "repair-result.json").is_file())
            self.assertTrue((run_dir / "trace.jsonl").is_file())
            self.assertTrue((run_dir / "chosen.diff").is_file())
            self.assertNotEqual("none", summary["chosen"])

    def test_strict_scenario_load_and_local_runner_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, demo_scenario(Path(temporary)) as demo:
            budget = Budget(
                max_rounds=1,
                max_candidates=1,
                max_validations=1,
                batch_size=1,
            )
            payload = {
                "schema_version": SCHEMA_VERSION,
                "task": demo.task.to_dict(),
                "locations": [demo.location.to_dict()],
                "candidates": [demo.candidates[0].to_dict()],
                "plan": demo.plan.to_dict(),
                "budget": budget.to_dict(),
            }
            path = Path(temporary) / "scenario.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_scenario(path)
            self.assertEqual(demo.task, loaded.task)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main(("repair", str(path), "--runner", "local"))
            self.assertEqual(2, code)
            self.assertIn("--allow-unsafe-local-exec", stderr.getvalue())

    def test_repair_and_validate_return_nonzero_without_verified_choice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = mock.Mock(candidate_id="candidate-1")
            scenario = mock.Mock(
                task=mock.Mock(task_id="task-1"),
                locations=(),
                candidates=(candidate,),
                plan=mock.Mock(),
                budget=Budget(
                    max_rounds=1,
                    max_candidates=1,
                    max_validations=1,
                    batch_size=1,
                ),
            )
            result = RepairResult(
                run_id="no-verified-choice",
                input_fingerprint="0" * 64,
                task_id="task-1",
                baseline=None,
                chosen=None,
                all_candidates=(),
                validations=(),
                attempts=1,
                cost=CostSummary(rounds=1, candidates_seen=1),
            )
            commands = (
                ("repair", "scenario.json"),
                ("validate", "scenario.json", candidate.candidate_id),
            )
            for command_args in commands:
                with (
                    self.subTest(command=command_args[0]),
                    mock.patch("vulnrepair.cli.load_scenario", return_value=scenario),
                    mock.patch("vulnrepair.cli._execute", new=mock.AsyncMock(return_value=result)),
                    redirect_stdout(io.StringIO()),
                ):
                    code = main(
                        (
                            *command_args,
                            "--runner",
                            "local",
                            "--allow-unsafe-local-exec",
                            "--output",
                            str(Path(temporary) / "runs"),
                        )
                    )
                self.assertEqual(1, code)


if __name__ == "__main__":
    unittest.main()
