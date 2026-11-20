"""Atomic, redacted JSON persistence for repair runs."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

from .contracts import ContractError, RepairResult

_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])"
    r"(?P<quote>[\"']?)(?P<key>[A-Za-z_][A-Za-z0-9_-]*)(?P=quote)"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;{}\[\]]+)"
)
_AUTHORIZATION = re.compile(
    r"(?i)([\"']?authorization[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|(?:bearer\s+)?[^\s,;}\]]+)"
)
_SECRET_ARGUMENT = re.compile(
    r"(?i)(--(?:api[_-]?key|access[_-]?token|token|password|secret)\s+)[^\s]+"
)
_SENSITIVE_FIELD = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|"
    r"secret|authorization|bearer|cookie|session|credential|private[_-]?key)(?:$|[_-])"
)
_SENSITIVE_FLAG = re.compile(
    r"(?i)^--(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|secret|"
    r"authorization|cookie|session|credential|private[_-]?key)$"
)


class Redactor:
    """Redact explicit values and common credential-shaped strings."""

    def __init__(self, sensitive_values: Iterable[str] = ()) -> None:
        self._sensitive_values = tuple(
            sorted((value for value in sensitive_values if value), key=len, reverse=True)
        )

    def text(self, value: str) -> str:
        try:
            structured = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            structured = None
        if isinstance(structured, (dict, list)):
            return json.dumps(
                self.value(structured),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        redacted = value
        for secret in self._sensitive_values:
            redacted = redacted.replace(secret, "[REDACTED]")
        redacted = _AUTHORIZATION.sub(r"\1[REDACTED]", redacted)
        redacted = _ASSIGNMENT.sub(_redact_assignment, redacted)
        redacted = _SECRET_ARGUMENT.sub(r"\1[REDACTED]", redacted)
        return redacted

    def value(self, value: Any, *, key: str | None = None) -> Any:
        # Diffs are content-addressed and must remain byte-for-byte consistent
        # with candidate_id. Command output, trace text, and metadata are redacted.
        if key != "diff" and key is not None and _is_sensitive_name(key):
            return "[REDACTED]"
        if isinstance(value, str):
            return value if key == "diff" else self.text(value)
        if isinstance(value, list):
            return self._sequence(value)
        if isinstance(value, dict):
            return {item_key: self.value(item, key=item_key) for item_key, item in value.items()}
        return value

    def _sequence(self, values: list[Any]) -> list[Any]:
        redacted: list[Any] = []
        redact_next = False
        for item in values:
            if redact_next:
                redacted.append("[REDACTED]")
                redact_next = False
                continue
            redacted.append(self.value(item))
            if isinstance(item, str) and _SENSITIVE_FLAG.fullmatch(item):
                redact_next = True
        return redacted


def _is_sensitive_name(name: str) -> bool:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name.strip("\"'"))
    return bool(_SENSITIVE_FIELD.search(normalized))


def _redact_assignment(match: re.Match[str]) -> str:
    if not _is_sensitive_name(match.group("key")):
        return match.group(0)
    quote = match.group("quote")
    return f"{quote}{match.group('key')}{quote}{match.group('separator')}[REDACTED]"


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


class JsonRunStore:
    """Stage every artifact privately, then atomically publish one run directory."""

    def __init__(
        self,
        root: Path,
        *,
        sensitive_values: Iterable[str] = (),
        allow_overwrite: bool = False,
        persistence_reserve_seconds: float = 1.0,
    ) -> None:
        if not math.isfinite(persistence_reserve_seconds) or persistence_reserve_seconds <= 0:
            raise ValueError("persistence_reserve_seconds must be finite and positive")
        self.root = Path(root)
        self.redactor = Redactor(sensitive_values)
        self.allow_overwrite = allow_overwrite
        self.persistence_reserve_seconds = persistence_reserve_seconds

    def _run_dir(self, run_id: str) -> Path:
        if not _SAFE_RUN_ID.fullmatch(run_id) or run_id in {".", ".."}:
            raise ContractError("run_id must be a safe path component")
        return self.root / run_id

    async def save(
        self,
        result: RepairResult,
        *,
        deadline: float | None = None,
    ) -> RepairResult:
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("run persistence deadline reached")
        state = _PersistenceState()
        worker = asyncio.create_task(asyncio.to_thread(self._save_sync, result, state, deadline))
        try:
            if deadline is None:
                return await asyncio.shield(worker)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("run persistence deadline reached")
            async with asyncio.timeout(remaining):
                return await asyncio.shield(worker)
        except TimeoutError:
            if state.cancel():
                return await _await_persistence_worker(worker)
            worker.add_done_callback(_consume_persistence_worker)
            raise
        except asyncio.CancelledError:
            committing = state.cancel()
            if committing:
                committed = await _await_persistence_worker(worker)
                if deadline is not None and time.monotonic() >= deadline:
                    return committed
            worker.add_done_callback(_consume_persistence_worker)
            raise

    def _save_sync(
        self,
        result: RepairResult,
        state: _PersistenceState | None = None,
        deadline: float | None = None,
    ) -> RepairResult:
        state = state or _PersistenceState()
        updated = self._charge_persistence_reserve(result)
        run_dir = self._run_dir(result.run_id)
        self.root.mkdir(parents=True, exist_ok=True)
        if run_dir.exists() and not self.allow_overwrite:
            raise ContractError(f"run already exists: {result.run_id}")
        if run_dir.exists() and not run_dir.is_dir():
            raise ContractError(f"run path is not a directory: {result.run_id}")
        staging = self.root / f".{result.run_id}.{uuid.uuid4().hex}.staging"
        staging.mkdir()
        trace_lines = [
            json.dumps(
                self.redactor.value(event.to_dict()),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for event in updated.trace
        ]
        trace_jsonl = "\n".join(trace_lines) + ("\n" if trace_lines else "")
        chosen_diff = updated.chosen.diff if updated.chosen is not None else ""
        payload = self.redactor.value(updated.to_dict())
        result_json = (
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        )
        published = False
        try:
            state.ensure_active(deadline)
            _atomic_write_text(staging / "trace.jsonl", trace_jsonl)
            state.ensure_active(deadline)
            _atomic_write_text(staging / "chosen.diff", chosen_diff)
            state.ensure_active(deadline)
            # The manifest is deliberately last inside the hidden staging tree.
            _atomic_write_text(staging / "repair-result.json", result_json)
            state.ensure_active(deadline)
            self._publish(staging, run_dir, state, deadline)
            published = True
            return updated
        finally:
            if not published:
                shutil.rmtree(staging, ignore_errors=True)

    def _charge_persistence_reserve(self, result: RepairResult) -> RepairResult:
        if result.cost.persistence_seconds > 0:
            return result
        return replace(
            result,
            cost=replace(
                result.cost,
                elapsed_seconds=result.cost.elapsed_seconds + self.persistence_reserve_seconds,
                persistence_seconds=self.persistence_reserve_seconds,
            ),
        )

    def _publish(
        self,
        staging: Path,
        run_dir: Path,
        state: _PersistenceState,
        deadline: float | None,
    ) -> None:
        # ``begin_commit`` and ``cancel`` serialize through one lock.  If commit
        # wins, the async caller waits for this non-cancellable atomic publish;
        # if cancellation wins, no public run directory can appear later.
        state.begin_commit(deadline)
        if not run_dir.exists():
            os.replace(staging, run_dir)
            return
        if not self.allow_overwrite:
            raise ContractError(f"run already exists: {run_dir.name}")

        backup = self.root / f".{run_dir.name}.{uuid.uuid4().hex}.backup"
        os.replace(run_dir, backup)
        try:
            os.replace(staging, run_dir)
        except BaseException:
            os.replace(backup, run_dir)
            raise
        else:
            shutil.rmtree(backup)

    async def load(self, run_dir: Path) -> RepairResult:
        return await asyncio.to_thread(self._load_sync, Path(run_dir))

    def _load_sync(self, run_dir: Path) -> RepairResult:
        path = run_dir / "repair-result.json"
        try:
            payload = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ContractError(f"unable to read repair result: {exc}") from exc
        return RepairResult.from_json(payload)


class _PersistenceState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancelled = False
        self._committing = False

    def cancel(self) -> bool:
        with self._lock:
            self._cancelled = True
            return self._committing

    def ensure_active(self, deadline: float | None) -> None:
        with self._lock:
            self._raise_if_inactive(deadline)

    def begin_commit(self, deadline: float | None) -> None:
        with self._lock:
            self._raise_if_inactive(deadline)
            self._committing = True

    def _raise_if_inactive(self, deadline: float | None) -> None:
        if self._cancelled:
            raise TimeoutError("run persistence was cancelled")
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("run persistence deadline reached")


async def _await_persistence_worker(
    worker: asyncio.Task[RepairResult],
) -> RepairResult:
    while not worker.done():
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError:
            continue
    return worker.result()


def _consume_persistence_worker(worker: asyncio.Task[RepairResult]) -> None:
    if not worker.cancelled():
        worker.exception()


__all__ = ["JsonRunStore", "Redactor"]
