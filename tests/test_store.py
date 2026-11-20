from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import vulnrepair.store as store_module
from vulnrepair.contracts import (
    BaselineResult,
    CommandResult,
    CommandSpec,
    ContractError,
    CostSummary,
    OverallVerdict,
    PatchCandidate,
    RepairResult,
    SecurityOutcome,
    SnapshotMetadata,
    StageResult,
    StageVerdict,
    TraceEvent,
    ValidationResult,
)
from vulnrepair.store import JsonRunStore, Redactor

DIFF = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-bad\n+good\n"


def result(*, run_id: str = "run-1", chosen: bool = True) -> RepairResult:
    patch = PatchCandidate(task_id="task-1", diff=DIFF, generated_by="fixture")
    command = CommandSpec(name="probe", argv=("probe", "--token", "abc123"))
    command_result = CommandResult(
        command=command,
        verdict=StageVerdict.PASS,
        returncode=0,
        stdout="token=abc123 extra-secret",
        stderr="Authorization: Bearer xyz",
        reason_code="ok",
    )
    stage = StageResult(
        stage="candidate.poc",
        verdict=StageVerdict.PASS,
        reason_code="blocked",
        command_result=command_result,
        security_outcome=SecurityOutcome.BLOCKED,
    )
    baseline_stage = StageResult(
        stage="baseline.poc",
        verdict=StageVerdict.PASS,
        reason_code="baseline_vulnerability_reproduced",
        command_result=command_result,
        security_outcome=SecurityOutcome.VULNERABLE,
    )
    baseline = BaselineResult(
        task_id="task-1",
        snapshot=SnapshotMetadata(commit="abc", tree_digest="tree", archive_sha256="archive"),
        stages=(baseline_stage,),
        usable=True,
        summary="baseline vulnerability evidence established",
    )
    validation = ValidationResult(
        candidate_id=patch.candidate_id,
        stages=(stage,),
        overall=OverallVerdict.VERIFIED_FIX,
    )
    return RepairResult(
        run_id=run_id,
        input_fingerprint="f" * 64,
        task_id="task-1",
        baseline=baseline,
        chosen=patch if chosen else None,
        all_candidates=(patch,),
        validations=(validation,),
        attempts=1,
        cost=CostSummary(candidates_seen=1, candidates_validated=1),
        trace=(
            TraceEvent(
                sequence=0,
                event="validated",
                task_id="task-1",
                message="Authorization: Bearer trace-secret",
            ),
        ),
    )


class JsonRunStoreTests(unittest.TestCase):
    def test_deadline_never_publishes_a_late_partial_or_complete_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = JsonRunStore(root)
            original_write = store_module._atomic_write_text

            def delayed_manifest(path: Path, content: str) -> None:
                if path.name == "repair-result.json":
                    time.sleep(0.2)
                original_write(path, content)

            async def exercise() -> None:
                loop_errors: list[dict[str, object]] = []
                asyncio.get_running_loop().set_exception_handler(
                    lambda _loop, context: loop_errors.append(context)
                )
                with mock.patch.object(store_module, "_atomic_write_text", delayed_manifest):
                    with self.assertRaises(TimeoutError):
                        await store.save(result(), deadline=time.monotonic() + 0.05)
                    self.assertFalse((root / "run-1").exists())
                    await asyncio.sleep(0.35)
                self.assertEqual([], loop_errors)

            asyncio.run(exercise())
            self.assertFalse((root / "run-1").exists())
            self.assertEqual([], list(root.glob(".*.staging")))

    def test_atomic_publish_is_a_bounded_non_cancellable_critical_section(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = JsonRunStore(root)
            original_replace = store_module.os.replace

            def delayed_directory_publish(source, destination) -> None:
                if str(source).endswith(".staging"):
                    time.sleep(0.2)
                original_replace(source, destination)

            def fast_staged_write(path: Path, content: str) -> None:
                path.write_text(content, encoding="utf-8")

            async def exercise() -> tuple[RepairResult, float]:
                started = time.monotonic()
                with (
                    mock.patch.object(store_module, "_atomic_write_text", fast_staged_write),
                    mock.patch.object(store_module.os, "replace", delayed_directory_publish),
                ):
                    stored = await store.save(result(), deadline=started + 0.05)
                return stored, time.monotonic() - started

            stored, elapsed = asyncio.run(exercise())
            self.assertGreaterEqual(elapsed, 0.18)
            self.assertTrue((root / stored.run_id / "repair-result.json").is_file())
            time.sleep(0.1)
            self.assertEqual([], list(root.glob(".*.staging")))

    def test_success_is_published_only_after_all_staged_artifacts_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = JsonRunStore(root)
            original_publish = store._publish
            observed = False

            def inspect_publish(staging, run_dir, cancelled, deadline) -> None:
                nonlocal observed
                self.assertFalse(run_dir.exists())
                self.assertEqual(
                    {"chosen.diff", "repair-result.json", "trace.jsonl"},
                    {path.name for path in staging.iterdir()},
                )
                observed = True
                original_publish(staging, run_dir, cancelled, deadline)

            with mock.patch.object(store, "_publish", side_effect=inspect_publish):
                stored = asyncio.run(store.save(result()))

            self.assertTrue(observed)
            self.assertTrue((root / stored.run_id / "repair-result.json").is_file())

    def test_structured_fields_json_text_and_adjacent_flags_are_redacted(self) -> None:
        redactor = Redactor()
        payload = {
            "token": "abc123",
            "nested": {"password": "hunter2"},
            "argv": ["client", "--api-key", "key-value", "--safe", "visible"],
            "message": '{"authorization":"Bearer secret-value","safe":"ok"}',
        }

        redacted = redactor.value(payload)
        rendered = json.dumps(redacted)

        for secret in ("abc123", "hunter2", "key-value", "secret-value"):
            self.assertNotIn(secret, rendered)
        self.assertIn("visible", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_prefixed_json_and_quoted_assignments_are_redacted(self) -> None:
        redactor = Redactor()
        messages = (
            'INFO {"token":"abc123"}',
            'payload={"password": "hunter2"}',
            'authorization = "Bearer xyz"',
            "cookie='session-value' safe=visible",
            'INFO {"client_secret":"client-value"}',
            "AWS_SECRET_ACCESS_KEY=aws-value",
            "db_password=db-value",
            "clientSecret=camel-value",
        )

        rendered = "\n".join(redactor.text(message) for message in messages)

        for secret in (
            "abc123",
            "hunter2",
            "xyz",
            "session-value",
            "client-value",
            "aws-value",
            "db-value",
            "camel-value",
        ):
            self.assertNotIn(secret, rendered)
        self.assertIn("safe=visible", rendered)
        self.assertGreaterEqual(rendered.count("[REDACTED]"), 8)

    def test_save_load_artifacts_and_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = JsonRunStore(Path(temporary), sensitive_values=("extra-secret",))
            original = result()
            stored = asyncio.run(store.save(original))
            run_dir = Path(temporary) / stored.run_id
            self.assertGreater(stored.cost.persistence_seconds, 0)
            self.assertGreaterEqual(stored.cost.elapsed_seconds, stored.cost.persistence_seconds)

            repair_path = run_dir / "repair-result.json"
            trace_path = run_dir / "trace.jsonl"
            chosen_path = run_dir / "chosen.diff"
            self.assertTrue(repair_path.is_file())
            self.assertTrue(trace_path.is_file())
            self.assertTrue(chosen_path.is_file())
            self.assertEqual(chosen_path.read_text(encoding="utf-8"), DIFF)

            combined = repair_path.read_text(encoding="utf-8") + trace_path.read_text(
                encoding="utf-8"
            )
            for secret in ("abc123", "extra-secret", "xyz", "trace-secret"):
                self.assertNotIn(secret, combined)
            self.assertIn("[REDACTED]", combined)

            restored = asyncio.run(store.load(run_dir))
            self.assertEqual(restored.run_id, original.run_id)
            self.assertEqual(restored.chosen, original.chosen)
            self.assertIn("[REDACTED]", restored.validations[0].stages[0].command_result.stdout)
            self.assertEqual(
                restored.baseline.stages[0].reason_code,
                "baseline_vulnerability_reproduced",
            )
            self.assertIn(
                "[REDACTED]",
                restored.baseline.stages[0].command_result.stdout,
            )

            trace_rows = [
                json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(trace_rows), 1)
            self.assertEqual(trace_rows[0]["sequence"], 0)

    def test_duplicate_run_id_is_rejected_without_modifying_existing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = JsonRunStore(Path(temporary))
            stored = asyncio.run(store.save(result()))
            run_dir = Path(temporary) / stored.run_id
            with self.assertRaises(ContractError):
                asyncio.run(store.save(result(chosen=False)))
            self.assertEqual((run_dir / "chosen.diff").read_text(encoding="utf-8"), DIFF)

    def test_explicit_overwrite_is_atomic_and_clears_chosen_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = JsonRunStore(Path(temporary), allow_overwrite=True)
            stored = asyncio.run(store.save(result()))
            run_dir = Path(temporary) / stored.run_id
            asyncio.run(store.save(result(chosen=False)))
            self.assertEqual((run_dir / "chosen.diff").read_text(encoding="utf-8"), "")
            self.assertEqual(list(run_dir.glob("*.tmp")), [])

    def test_unsafe_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = JsonRunStore(Path(temporary))
            with self.assertRaises(ContractError):
                asyncio.run(store.save(result(run_id="../escape")))


if __name__ == "__main__":
    unittest.main()
