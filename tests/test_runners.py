from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from vulnrepair.contracts import CommandResult, CommandSpec, StageVerdict
from vulnrepair.runners import DockerCommandRunner, LocalCommandRunner, RunnerLimits

PINNED_IMAGE = "example.invalid/vulnrepair@sha256:" + "a" * 64


def command(*argv: str, timeout: float = 5.0, cwd: str = ".") -> CommandSpec:
    return CommandSpec(name="test-command", argv=tuple(argv), timeout_seconds=timeout, cwd=cwd)


class LocalCommandRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)

    def run_async(self, coroutine: object) -> object:
        return asyncio.run(coroutine)  # type: ignore[arg-type]

    def test_local_execution_refuses_without_explicit_opt_in(self) -> None:
        result = self.run_async(
            LocalCommandRunner().run(
                command(sys.executable, "-c", "print('unsafe')"), self.workspace
            )
        )
        self.assertEqual(result.verdict, StageVerdict.INFRA_ERROR)
        self.assertEqual(result.reason_code, "local_execution_disabled")

    def test_local_runner_executes_argv_without_shell(self) -> None:
        result = self.run_async(
            LocalCommandRunner(allow_unsafe=True).run(
                command(sys.executable, "-c", "print('ok')"),
                self.workspace,
            )
        )
        self.assertEqual(result.verdict, StageVerdict.PASS)
        self.assertEqual(result.stdout.strip(), "ok")
        self.assertEqual(result.returncode, 0)

    def test_shell_string_and_workspace_escape_are_rejected(self) -> None:
        string_spec = CommandSpec(name="bad", argv="echo bad")  # type: ignore[arg-type]
        result = self.run_async(
            LocalCommandRunner(allow_unsafe=True).run(string_spec, self.workspace)
        )
        self.assertEqual(result.reason_code, "invalid_command")
        traversal = command(sys.executable, "-c", "pass", cwd="../outside")
        result = self.run_async(
            LocalCommandRunner(allow_unsafe=True).run(traversal, self.workspace)
        )
        self.assertEqual(result.reason_code, "invalid_command")

    def test_host_secrets_are_not_inherited(self) -> None:
        with mock.patch.dict(os.environ, {"VULNREPAIR_SECRET_TOKEN": "host-secret"}):
            runner = LocalCommandRunner(allow_unsafe=True)
        script = "import os; print(os.environ.get('VULNREPAIR_SECRET_TOKEN', '<missing>'))"
        result = self.run_async(runner.run(command(sys.executable, "-c", script), self.workspace))
        self.assertEqual(result.stdout.strip(), "<missing>")

    def test_output_is_redacted_sanitized_and_bounded(self) -> None:
        runner = LocalCommandRunner(
            allow_unsafe=True,
            limits=RunnerLimits(max_output_bytes=128),
            environment={"PUBLIC_VALUE": "secret-value"},
        )
        script = "import os; print('\\x1b[31m' + os.environ['PUBLIC_VALUE'] + '\\x1b[0m'); print('x' * 1000)"
        result = self.run_async(runner.run(command(sys.executable, "-c", script), self.workspace))
        self.assertEqual(result.verdict, StageVerdict.PASS)
        self.assertTrue(result.truncated)
        self.assertEqual(result.reason_code, "output_truncated")
        self.assertIn("[REDACTED]", result.stdout)
        self.assertNotIn("secret-value", result.stdout)
        self.assertNotIn("\x1b", result.stdout)
        self.assertLessEqual(
            len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")), 128
        )

    def test_truncation_cannot_expose_a_secret_prefix(self) -> None:
        runner = LocalCommandRunner(
            allow_unsafe=True,
            limits=RunnerLimits(max_output_bytes=7),
            environment={"PUBLIC_VALUE": "secret-value"},
        )
        script = "import os,sys; sys.stdout.write(os.environ['PUBLIC_VALUE'])"
        result = self.run_async(runner.run(command(sys.executable, "-c", script), self.workspace))
        self.assertTrue(result.truncated)
        self.assertNotIn("secret", result.stdout)
        self.assertLessEqual(
            len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")), 7
        )

    def test_nonzero_exit_is_a_command_failure_not_infrastructure_error(self) -> None:
        result = self.run_async(
            LocalCommandRunner(allow_unsafe=True).run(
                command(sys.executable, "-c", "raise SystemExit(7)"),
                self.workspace,
            )
        )
        self.assertEqual(result.verdict, StageVerdict.FAIL)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.reason_code, "nonzero_exit")

    def test_timeout_terminates_the_command(self) -> None:
        started = time.monotonic()
        result = self.run_async(
            LocalCommandRunner(allow_unsafe=True).run(
                command(sys.executable, "-c", "import time; time.sleep(30)", timeout=0.1),
                self.workspace,
            )
        )
        self.assertEqual(result.verdict, StageVerdict.TIMEOUT)
        self.assertEqual(result.reason_code, "timeout")
        self.assertLess(time.monotonic() - started, 5)

    def test_outer_cancellation_terminates_process_tree(self) -> None:
        started_marker = self.workspace / "started"
        leaked_marker = self.workspace / "leaked"
        child_code = (
            "import time; from pathlib import Path; "
            f"time.sleep(0.8); Path({str(leaked_marker)!r}).write_text('leaked')"
        )
        parent_code = (
            "import subprocess, sys, time; from pathlib import Path; "
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            f"Path({str(started_marker)!r}).write_text('started'); time.sleep(30)"
        )

        async def cancel_running_command() -> None:
            runner = LocalCommandRunner(allow_unsafe=True)
            running = asyncio.create_task(
                runner.run(command(sys.executable, "-c", parent_code), self.workspace)
            )
            for _ in range(300):
                if started_marker.exists():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(started_marker.exists(), "test process did not start")
            running.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await running
            await asyncio.sleep(1.0)

        asyncio.run(cancel_running_command())
        self.assertFalse(leaked_marker.exists(), "cancelled descendant survived process cleanup")

    @unittest.skipUnless(os.name == "nt", "requires Windows Job Objects")
    def test_windows_job_closes_after_parent_exits(self) -> None:
        leaked_marker = self.workspace / "leaked-after-parent"
        child_code = (
            "import time; from pathlib import Path; "
            f"time.sleep(0.8); Path({str(leaked_marker)!r}).write_text('leaked')"
        )
        parent_code = (
            "import subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            "print('parent-finished')"
        )

        result = self.run_async(
            LocalCommandRunner(allow_unsafe=True).run(
                command(sys.executable, "-c", parent_code), self.workspace
            )
        )
        time.sleep(1.0)

        self.assertEqual(result.verdict, StageVerdict.PASS)
        self.assertEqual(result.stdout.strip(), "parent-finished")
        self.assertFalse(leaked_marker.exists(), "detached descendant escaped the Windows job")

    def test_sensitive_explicit_environment_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            LocalCommandRunner(allow_unsafe=True, environment={"API_KEY": "should-not-pass"})


class DockerCommandRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.harness = self.root / "harness"
        self.harness.mkdir()
        self.docker = self.root / ("docker.exe" if os.name == "nt" else "docker")
        self.docker.write_bytes(b"")

    def make_runner(self, **kwargs: object) -> DockerCommandRunner:
        return DockerCommandRunner(
            image=PINNED_IMAGE,
            docker_executable=str(self.docker),
            **kwargs,
        )

    def test_mutable_image_reference_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            DockerCommandRunner(image="python:3.11", docker_executable=str(self.docker))
        DockerCommandRunner(image="sha256:" + "b" * 64, docker_executable=str(self.docker))

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "getuid") and os.getuid() != 0,
        "requires non-root POSIX host",
    )
    def test_default_container_identity_matches_snapshot_owner(self) -> None:
        runner = self.make_runner()
        self.assertEqual(runner.docker_limits.user, f"{os.getuid()}:{os.getgid()}")
        # Owner-only workspace permissions remain usable because the numeric
        # identity inside the container matches the coordinator.
        self.workspace.chmod(0o700)
        argv = runner._build_docker_argv(
            command("python", "-c", "open('artifact','w').write('ok')"),
            self.workspace.resolve(),
            PurePosixPath("."),
            "container-name",
        )
        user_index = argv.index("--user")
        self.assertEqual(argv[user_index + 1], f"{os.getuid()}:{os.getgid()}")

    def test_hardened_docker_arguments_and_read_only_harness_mount(self) -> None:
        runner = self.make_runner(harness_dir=self.harness)
        spec = command("python", "/harness/poc.py")
        argv = runner._build_docker_argv(
            spec, self.workspace.resolve(), PurePosixPath("."), "container-name"
        )
        joined = " ".join(argv)
        self.assertIn("--pull=never", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("no-new-privileges:true", argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--memory", argv)
        self.assertIn("--cpus", argv)
        self.assertIn("--user", argv)
        self.assertIn("--tmpfs", argv)
        self.assertIn("--rm", argv)
        network_index = argv.index("--network")
        self.assertEqual(argv[network_index + 1], "none")
        self.assertIn("dst=/harness,readonly", joined)
        self.assertNotIn("--privileged", argv)
        self.assertEqual(argv[-3:], (PINNED_IMAGE, "python", "/harness/poc.py"))

    def test_timeout_forces_container_removal(self) -> None:
        runner = self.make_runner()
        spec = command("python", "-c", "pass")
        calls: list[tuple[str, ...]] = []

        async def fake_execute(
            incoming_spec: CommandSpec,
            argv: tuple[str, ...],
            **_kwargs: object,
        ) -> CommandResult:
            calls.append(tuple(argv))
            if len(calls) == 1:
                return CommandResult(
                    command=incoming_spec,
                    verdict=StageVerdict.TIMEOUT,
                    reason_code="timeout",
                )
            return CommandResult(
                command=incoming_spec,
                verdict=StageVerdict.PASS,
                returncode=0,
                reason_code="ok",
            )

        with mock.patch("vulnrepair.runners._execute_process", side_effect=fake_execute):
            result = asyncio.run(runner.run(spec, self.workspace))
        self.assertEqual(result.verdict, StageVerdict.TIMEOUT)
        self.assertEqual(len(calls), 2)
        first_name = calls[0][calls[0].index("--name") + 1]
        self.assertEqual(calls[1][-3:], ("rm", "-f", first_name))

    def test_outer_cancellation_forces_container_removal(self) -> None:
        runner = self.make_runner()
        spec = command("python", "-c", "pass")
        calls: list[tuple[str, ...]] = []
        started = asyncio.Event()

        async def fake_execute(
            incoming_spec: CommandSpec,
            argv: tuple[str, ...],
            **_kwargs: object,
        ) -> CommandResult:
            calls.append(tuple(argv))
            if len(calls) == 1:
                started.set()
                await asyncio.Future()
                raise AssertionError("unreachable")
            return CommandResult(
                command=incoming_spec,
                verdict=StageVerdict.PASS,
                returncode=0,
                reason_code="ok",
            )

        async def cancel_running_container() -> None:
            with mock.patch("vulnrepair.runners._execute_process", side_effect=fake_execute):
                running = asyncio.create_task(runner.run(spec, self.workspace))
                await started.wait()
                running.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await running

        asyncio.run(cancel_running_container())
        self.assertEqual(len(calls), 2)
        first_name = calls[0][calls[0].index("--name") + 1]
        self.assertEqual(calls[1][-3:], ("rm", "-f", first_name))

    def test_cancellation_during_timeout_cleanup_finishes_removal(self) -> None:
        runner = self.make_runner()
        spec = command("python", "-c", "pass")
        calls: list[tuple[str, ...]] = []
        cleanup_started = asyncio.Event()
        release_cleanup = asyncio.Event()

        async def fake_execute(
            incoming_spec: CommandSpec,
            argv: tuple[str, ...],
            **_kwargs: object,
        ) -> CommandResult:
            calls.append(tuple(argv))
            if len(calls) == 1:
                return CommandResult(
                    command=incoming_spec,
                    verdict=StageVerdict.TIMEOUT,
                    reason_code="timeout",
                )
            cleanup_started.set()
            await release_cleanup.wait()
            return CommandResult(
                command=incoming_spec,
                verdict=StageVerdict.PASS,
                returncode=0,
                reason_code="ok",
            )

        async def cancel_during_cleanup() -> None:
            with mock.patch("vulnrepair.runners._execute_process", side_effect=fake_execute):
                running = asyncio.create_task(runner.run(spec, self.workspace))
                await cleanup_started.wait()
                running.cancel()
                await asyncio.sleep(0)
                self.assertFalse(running.done())
                release_cleanup.set()
                with self.assertRaises(asyncio.CancelledError):
                    await running

        asyncio.run(cancel_during_cleanup())
        self.assertEqual(len(calls), 2)
        first_name = calls[0][calls[0].index("--name") + 1]
        self.assertEqual(calls[1][-3:], ("rm", "-f", first_name))

    def test_docker_infrastructure_exit_codes_are_not_command_failures(self) -> None:
        runner = self.make_runner()
        spec = command("missing-command")
        calls = 0

        async def fake_execute(
            incoming_spec: CommandSpec,
            _argv: tuple[str, ...],
            **_kwargs: object,
        ) -> CommandResult:
            nonlocal calls
            calls += 1
            if calls == 1:
                return CommandResult(
                    command=incoming_spec,
                    verdict=StageVerdict.FAIL,
                    returncode=127,
                    reason_code="nonzero_exit",
                )
            return CommandResult(
                command=incoming_spec,
                verdict=StageVerdict.PASS,
                returncode=0,
                reason_code="ok",
            )

        with mock.patch("vulnrepair.runners._execute_process", side_effect=fake_execute):
            result = asyncio.run(runner.run(spec, self.workspace))
        self.assertEqual(result.verdict, StageVerdict.INFRA_ERROR)
        self.assertEqual(result.reason_code, "container_command_missing")
        self.assertEqual(calls, 2)

    def test_sensitive_container_environment_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.make_runner(container_environment={"PASSWORD": "not-allowed"})


if __name__ == "__main__":
    unittest.main()
