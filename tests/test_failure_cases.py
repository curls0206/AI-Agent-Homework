"""Failure cases the Agent must handle without ever claiming a fix (assignment 2)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnrepair.cli import main
from vulnrepair.course_fixtures import write_fixture

IMAGE = os.environ.get("VULNREPAIR_PODMAN_IMAGE")
MISSING_IMAGE = "sha256:" + "0" * 64
DEAD_LLM_HOST = "http://127.0.0.1:9"


def _repair(scenario: Path, runs: Path, *extra: str, image: str | None = None) -> dict:
    harness = json.loads(scenario.read_text(encoding="utf-8"))["plan"]["harness"]["root"]
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = main(
            (
                "repair", str(scenario), "--runner", "podman", "--image", image or IMAGE or "",
                "--harness-dir", harness, "--output", str(runs), "--max-rounds", "2", *extra,
            )
        )
    summary = json.loads(stdout.getvalue())
    result = json.loads(
        (Path(summary["artifact_dir"]) / "repair-result.json").read_text(encoding="utf-8")
    )
    return {"code": code, "summary": summary, "result": result}


def _events(result: dict) -> list[str]:
    return [event["event"] for event in result["trace"]]


def _leftover_containers() -> str:
    return subprocess.run(
        ("podman", "ps", "-a", "--filter", "name=vulnrepair-", "--format", "{{.ID}}"),
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()


@unittest.skipUnless(IMAGE, "Podman gate supplies VULNREPAIR_PODMAN_IMAGE")
class FailureCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_llm_server_unreachable_ends_without_a_fix(self) -> None:
        scenario = write_fixture("cwe79", self.root)
        out = _repair(
            scenario, self.root / "runs",
            "--generator", "ollama-replacement",
            "--ollama-host", DEAD_LLM_HOST, "--ollama-model", "llama3.3:70b",
            "--ollama-timeout-seconds", "5",
        )
        self.assertEqual(1, out["code"])
        self.assertIsNone(out["result"]["chosen"])
        events = _events(out["result"])
        self.assertIn("baseline_ready", events)
        self.assertIn("provider_errors", events)
        self.assertIn("round_empty", events)
        self.assertNotIn("candidate_validated", events)

    def test_missing_container_image_is_infra_error_not_success(self) -> None:
        scenario = write_fixture("cwe79", self.root)
        out = _repair(scenario, self.root / "runs", image=MISSING_IMAGE)
        self.assertEqual(1, out["code"])
        self.assertIsNone(out["result"]["chosen"])
        self.assertIn("baseline_unusable", _events(out["result"]))
        reasons = {s["reason_code"] for s in out["result"]["baseline"]["stages"]}
        self.assertTrue(any(code.endswith("_run_error") for code in reasons), reasons)

    def test_validation_timeout_is_not_success_and_removes_container(self) -> None:
        scenario = write_fixture("cwe79", self.root)
        payload = json.loads(scenario.read_text(encoding="utf-8"))
        payload["plan"]["build_commands"] = [
            {
                "schema_version": "1.0", "name": "slow-build", "cwd": ".", "required": True,
                "argv": ["python", "-c", "import time; time.sleep(60)"], "timeout_seconds": 3,
            }
        ]
        scenario.write_text(json.dumps(payload), encoding="utf-8")
        out = _repair(scenario, self.root / "runs")
        self.assertEqual(1, out["code"])
        self.assertIsNone(out["result"]["chosen"])
        self.assertIn("baseline_unusable", _events(out["result"]))
        verdicts = {s["verdict"] for s in out["result"]["baseline"]["stages"]}
        self.assertIn("timeout", verdicts)
        self.assertEqual("", _leftover_containers())


if __name__ == "__main__":
    unittest.main()
