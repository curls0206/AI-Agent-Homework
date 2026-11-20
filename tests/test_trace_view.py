from __future__ import annotations

import asyncio
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from vulnrepair.cli import main
from vulnrepair.store import JsonRunStore
from vulnrepair.trace_view import render_react_trace


class TraceViewTests(unittest.TestCase):
    def test_demo_trace_shows_decision_action_observation_and_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    ("demo", "--runner", "local", "--allow-unsafe-local-exec", "--output", tmp)
                )
            self.assertEqual(0, code)
            run_dir = Path(json.loads(stdout.getvalue())["artifact_dir"])
            result = asyncio.run(JsonRunStore(run_dir.parent).load(run_dir))

        text = render_react_trace(result)
        for expected in ("Input", "Action", "Observation", "Decision", "Result"):
            self.assertIn(expected, text)
        self.assertIn("Oracle.baseline", text)
        self.assertIn("verdict=verified_fix", text)
        self.assertIn("verdict=rejected", text)
        self.assertIn("選用 verified_fix 候選", text)

    def test_show_trace_command_prints_the_same_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                main(("demo", "--runner", "local", "--allow-unsafe-local-exec", "--output", tmp))
            run_dir = Path(json.loads(stdout.getvalue())["artifact_dir"])
            shown = io.StringIO()
            with contextlib.redirect_stdout(shown):
                code = main(("show-trace", str(run_dir)))
        self.assertEqual(0, code)
        self.assertIn("Tool Call: Oracle.validate", shown.getvalue())


if __name__ == "__main__":
    unittest.main()
