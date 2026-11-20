from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnrepair.cli import load_scenario, main
from vulnrepair.contracts import PatchCandidate
from vulnrepair.course_fixtures import FIXTURES, fixture_names, write_fixture

IMAGE = os.environ.get("VULNREPAIR_PODMAN_IMAGE")

GOOD_APP = {
    "cwe79": (
        "from html import escape\n\n\n"
        "def render_name(name: str) -> str:\n"
        '    return f"<p>{escape(name)}</p>"\n'
    ),
    "cwe22": (
        "import os\n\n"
        'BASE_DIR = "files"\n\n\n'
        "def read_file(name: str) -> str:\n"
        "    base = os.path.realpath(BASE_DIR)\n"
        "    path = os.path.realpath(os.path.join(base, name))\n"
        "    if os.path.commonpath([base, path]) != base:\n"
        '        raise ValueError("path escapes base directory")\n'
        '    with open(path, encoding="utf-8") as handle:\n'
        "        return handle.read()\n"
    ),
    "cwe89": (
        "import sqlite3\n\n\n"
        "def find_user(conn: sqlite3.Connection, username: str) -> list[tuple[int, str]]:\n"
        '    query = "SELECT id, username FROM users WHERE username = ?"\n'
        "    return conn.execute(query, (username,)).fetchall()\n"
    ),
    "cwe78": (
        "import subprocess\n\n\n"
        "def check_host(host: str) -> str:\n"
        "    result = subprocess.run(\n"
        '        ["echo", "checking", host], capture_output=True, text=True, check=False\n'
        "    )\n"
        "    return result.stdout\n"
    ),
}


def _git_diff_of(repo: Path, new_app: str) -> str:
    (repo / "app.py").write_text(new_app, encoding="utf-8", newline="\n")
    diff = subprocess.run(
        ("git", "diff", "--", "app.py"), cwd=repo, check=True, capture_output=True, text=True
    ).stdout
    subprocess.run(("git", "checkout", "--", "app.py"), cwd=repo, check=True, capture_output=True)
    return diff


class FixtureScenarioTests(unittest.TestCase):
    def test_every_fixture_produces_a_loadable_scenario(self) -> None:
        for name in fixture_names():
            for mode in ("located", "zero"):
                with self.subTest(name=name, mode=mode), tempfile.TemporaryDirectory() as tmp:
                    scenario = load_scenario(write_fixture(name, Path(tmp), mode=mode))
                    self.assertEqual(FIXTURES[name].cwe_id, scenario.task.cwe_id)
                    self.assertEqual((), scenario.candidates)
                    self.assertEqual(1 if mode == "located" else 0, len(scenario.locations))

    def test_location_lines_cover_the_vulnerable_function(self) -> None:
        for name, spec in FIXTURES.items():
            with self.subTest(name=name):
                lines = spec.files["app.py"].splitlines()
                text = "\n".join(lines[spec.location.start_line - 1 : spec.location.end_line])
                self.assertIn(f"def {spec.location.function_name}", text)

    def test_rationale_does_not_prescribe_the_fix(self) -> None:
        banned = ("escape", "parameter", "realpath", "commonpath", "shlex", "sanitize", "?")
        for name, spec in FIXTURES.items():
            with self.subTest(name=name):
                rationale = spec.location.rationale.lower()
                self.assertFalse(any(word in rationale for word in banned), rationale)

    def test_unknown_fixture_and_existing_directory_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                write_fixture("nope", Path(tmp))
            write_fixture("cwe79", Path(tmp))
            with self.assertRaises(ValueError):
                write_fixture("cwe79", Path(tmp))


@unittest.skipUnless(IMAGE, "Podman gate supplies VULNREPAIR_PODMAN_IMAGE")
class FixtureOracleInPodmanTests(unittest.TestCase):
    def test_good_fix_is_verified_and_noop_fix_is_rejected(self) -> None:
        for name in fixture_names():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                scenario_path = write_fixture(name, Path(tmp))
                scenario = load_scenario(scenario_path)
                repo = Path(scenario.task.repo_path)
                good = _git_diff_of(repo, GOOD_APP[name])
                noop = _git_diff_of(repo, FIXTURES[name].files["app.py"] + "\n# reviewed\n")
                payload = json.loads(scenario_path.read_text(encoding="utf-8"))
                payload["candidates"] = [
                    PatchCandidate(
                        task_id=scenario.task.task_id,
                        diff=diff,
                        target_location=None,
                        generated_by="test",
                        rationale=label,
                    ).to_dict()
                    for diff, label in ((good, "good"), (noop, "noop"))
                ]
                scenario_path.write_text(json.dumps(payload), encoding="utf-8")
                runs = Path(tmp) / "runs"
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    code = main(
                        ("repair", str(scenario_path), "--runner", "podman", "--image", IMAGE or "",
                         "--harness-dir", scenario.plan.harness.root,
                         "--output", str(runs), "--max-rounds", "1", "--batch-size", "2")
                    )
                self.assertEqual(0, code, stdout.getvalue())
                summary = json.loads(stdout.getvalue())
                result = json.loads(
                    (Path(summary["artifact_dir"]) / "repair-result.json").read_text(encoding="utf-8")
                )
                by_candidate = {v["candidate_id"]: v["overall"] for v in result["validations"]}
                self.assertEqual(["rejected", "verified_fix"], sorted(by_candidate.values()))
                self.assertEqual("verified_fix", by_candidate[result["chosen"]["candidate_id"]])


if __name__ == "__main__":
    unittest.main()
