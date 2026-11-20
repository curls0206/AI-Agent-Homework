"""Run the three assignment-2 failure cases and save their traces as evidence files.

Runs inside the Agent container (see README):
    podman run --rm --privileged --network=host -v vulnrepair-store:/var/lib/containers \
        -v "<host dir>:/out" vulnrepair-agent evidence
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import os
import tempfile
from pathlib import Path

from vulnrepair.cli import main
from vulnrepair.course_fixtures import write_fixture
from vulnrepair.store import JsonRunStore
from vulnrepair.trace_view import render_react_trace

MISSING_IMAGE = "sha256:" + "0" * 64


def run_case(
    label: str, scenario: Path, image: str, out: Path, extra: tuple[str, ...] = ()
) -> None:
    harness = json.loads(scenario.read_text(encoding="utf-8"))["plan"]["harness"]["root"]
    runs = scenario.parent / "runs"
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = main(
            ("repair", str(scenario), "--runner", "podman", "--image", image,
             "--harness-dir", harness, "--output", str(runs), "--max-rounds", "2", *extra)
        )
    summary = json.loads(stdout.getvalue())
    run_dir = Path(summary["artifact_dir"])
    result = asyncio.run(JsonRunStore(run_dir.parent).load(run_dir))
    (out / f"{label}.trace.txt").write_text(render_react_trace(result) + "\n", encoding="utf-8")
    (out / f"{label}.result.json").write_text(
        (run_dir / "repair-result.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    print(f"{label}: exit={code} chosen={summary['chosen']}")


def main_cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=os.environ.get("VULNREPAIR_SANDBOX_IMAGE"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not args.image:
        parser.error("--image or VULNREPAIR_SANDBOX_IMAGE is required")
    args.out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        case = write_fixture("cwe79", root / "llm_down")
        run_case(
            "failure1_llm_unreachable", case, args.image, args.out,
            ("--generator", "ollama-replacement", "--ollama-host", "http://127.0.0.1:9",
             "--ollama-model", "llama3.3:70b", "--ollama-timeout-seconds", "5"),
        )
        case = write_fixture("cwe79", root / "no_image")
        run_case("failure2_image_missing", case, MISSING_IMAGE, args.out)

        case = write_fixture("cwe79", root / "slow")
        payload = json.loads(case.read_text(encoding="utf-8"))
        payload["plan"]["build_commands"] = [
            {"schema_version": "1.0", "name": "slow-build", "cwd": ".", "required": True,
             "argv": ["python", "-c", "import time; time.sleep(60)"], "timeout_seconds": 3}
        ]
        case.write_text(json.dumps(payload), encoding="utf-8")
        run_case("failure3_timeout", case, args.image, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
