from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from vulnrepair.adapters import (
    InMemoryRepairMemory,
    PolicyCritic,
    StaticGenerator,
    StaticLocalizer,
)
from vulnrepair.contracts import (
    Budget,
    CommandSpec,
    StageVerdict,
    TrustedHarness,
    ValidationPlan,
)
from vulnrepair.demo import GOOD_DIFF, STILL_VULNERABLE_DIFF, demo_scenario
from vulnrepair.harness import compute_harness_digest
from vulnrepair.oracle import VerificationOracle
from vulnrepair.orchestrator import RepairOrchestrator
from vulnrepair.runners import DockerLimits, PodmanCommandRunner, RunnerLimits

IMAGE = os.environ.get("VULNREPAIR_PODMAN_IMAGE")


@unittest.skipUnless(IMAGE, "Podman isolation gate supplies VULNREPAIR_PODMAN_IMAGE")
class PodmanIsolationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name) / "workspace"
        self.workspace.mkdir()
        self.runner = PodmanCommandRunner(
            image=IMAGE or "sha256:" + "0" * 64,
            limits=RunnerLimits(max_output_bytes=1_024),
            docker_limits=DockerLimits(
                pids_limit=32,
                memory_bytes=64 * 1024 * 1024,
                cpus=0.5,
                tmpfs_bytes=8 * 1024 * 1024,
            ),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(self, name: str, code: str, timeout: float = 10):
        return asyncio.run(
            self.runner.run(
                CommandSpec(
                    name=name,
                    argv=("python", "-c", code),
                    timeout_seconds=timeout,
                ),
                self.workspace,
            )
        )

    def test_non_root_read_only_root_and_writable_workspace(self) -> None:
        code = (
            "import os, pathlib; "
            "assert os.geteuid() != 0; "
            "state={'blocked': False}; "
            "exec(\"try:\\n pathlib.Path('/blocked').write_text('x')\\n"
            "except OSError:\\n state['blocked']=True\"); "
            "assert state['blocked']; pathlib.Path('artifact.txt').write_text('ok')"
        )
        result = self.run_command("filesystem-boundary", code)
        self.assertIs(result.verdict, StageVerdict.PASS, result.stderr)
        self.assertEqual("ok", (self.workspace / "artifact.txt").read_text(encoding="utf-8"))

    def test_network_is_disabled(self) -> None:
        code = (
            "import socket; s=socket.socket(); s.settimeout(0.5); "
            "assert s.connect_ex(('1.1.1.1', 53)) != 0"
        )
        result = self.run_command("network-none", code)
        self.assertIs(result.verdict, StageVerdict.PASS, result.stderr)

    def test_cgroup_limits_are_visible(self) -> None:
        code = (
            "from pathlib import Path; "
            "memory=Path('/sys/fs/cgroup/memory.max'); "
            "pids=Path('/sys/fs/cgroup/pids.max'); "
            "cpu=Path('/sys/fs/cgroup/cpu.max'); "
            "assert memory.is_file(), 'memory.max is unavailable'; "
            "assert pids.is_file(), 'pids.max is unavailable'; "
            "assert cpu.is_file(), 'cpu.max is unavailable'; "
            "assert memory.read_text().strip() == '67108864', memory.read_text(); "
            "assert pids.read_text().strip() == '32', pids.read_text(); "
            "quota,period=cpu.read_text().split(); "
            "assert quota != 'max', cpu.read_text(); "
            "assert abs(int(quota)/int(period)-0.5) < 1e-9, cpu.read_text()"
        )
        result = self.run_command("resource-limits", code)
        self.assertIs(result.verdict, StageVerdict.PASS, result.stderr)

    def test_output_is_bounded(self) -> None:
        result = self.run_command("output-cap", "print('x' * 100000)")
        self.assertIs(result.verdict, StageVerdict.PASS)
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 1_024)

    def test_timeout_removes_container(self) -> None:
        result = self.run_command("timeout-cleanup", "import time; time.sleep(30)", timeout=0.2)
        self.assertIs(result.verdict, StageVerdict.TIMEOUT)
        remaining = subprocess.run(
            ("podman", "ps", "--filter", "name=vulnrepair-", "--format", "{{.ID}}"),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual("", remaining.stdout.strip())

    def test_full_oracle_flow_runs_inside_podman(self) -> None:
        with demo_scenario(Path(self.temporary.name)) as scenario:
            runner = PodmanCommandRunner(
                image=IMAGE or "sha256:" + "0" * 64,
                harness_dir=scenario.harness,
                docker_limits=DockerLimits(
                    pids_limit=32,
                    memory_bytes=64 * 1024 * 1024,
                    cpus=0.5,
                    tmpfs_bytes=8 * 1024 * 1024,
                ),
            )
            candidates = tuple(
                candidate
                for candidate in scenario.candidates
                if candidate.diff in {GOOD_DIFF, STILL_VULNERABLE_DIFF}
            )
            plan = ValidationPlan(
                harness=TrustedHarness(
                    root=str(scenario.harness),
                    digest_sha256=compute_harness_digest(scenario.harness),
                ),
                build_commands=(
                    CommandSpec(
                        name="compile",
                        argv=("python", "-m", "py_compile", "app.py"),
                        timeout_seconds=20,
                    ),
                ),
                test_commands=(
                    CommandSpec(
                        name="regression",
                        argv=("python", "test_regression.py"),
                        timeout_seconds=20,
                    ),
                ),
                poc_command=CommandSpec(
                    name="xss-poc",
                    argv=("python", "/harness/poc.py"),
                    timeout_seconds=20,
                ),
            )
            orchestrator = RepairOrchestrator(
                localizer=StaticLocalizer((scenario.location,)),
                generator=StaticGenerator(candidates),
                critic=PolicyCritic(),
                oracle=VerificationOracle(runner),
                memory=InMemoryRepairMemory(),
                budget=Budget(
                    max_rounds=1,
                    max_candidates=2,
                    max_validations=2,
                    max_elapsed_seconds=120,
                    batch_size=2,
                ),
            )
            result = asyncio.run(orchestrator.repair(scenario.task, plan))
            self.assertIsNotNone(result.chosen)
            self.assertEqual(GOOD_DIFF, result.chosen.diff)


if __name__ == "__main__":
    unittest.main()
