"""Versioned data contracts shared by every framework component.

The module intentionally uses only the standard library.  Persisted contracts
are immutable, reject unknown fields, and round-trip through JSON without
silently accepting a schema written by a newer implementation.
"""

from __future__ import annotations

import hashlib
import json
import math
import types
import unicodedata
from dataclasses import MISSING, dataclass, fields, is_dataclass
from enum import Enum
from typing import Any, ClassVar, TypeVar, Union, get_args, get_origin, get_type_hints

SCHEMA_VERSION = "1.0"


class ContractError(ValueError):
    """Base exception for malformed or unsupported contract data."""


class UnknownFieldError(ContractError):
    """Raised when serialized input contains an unrecognized field."""


class SchemaVersionError(ContractError):
    """Raised when serialized input uses an unsupported schema version."""


class StageVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    TIMEOUT = "timeout"
    INFRA_ERROR = "infra_error"
    SKIPPED = "skipped"


class SecurityOutcome(str, Enum):
    VULNERABLE = "vulnerable"
    BLOCKED = "blocked"
    CLEAN = "clean"
    FINDING_PRESENT = "finding_present"
    HARNESS_ERROR = "harness_error"
    NOT_AVAILABLE = "not_available"


class OverallVerdict(str, Enum):
    VERIFIED_FIX = "verified_fix"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    INFRA_ERROR = "infra_error"


class CritiqueVerdict(str, Enum):
    PASS = "pass"
    REJECT = "reject"


TContract = TypeVar("TContract", bound="JsonContract")


def _require_nonempty(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{name} must be a non-empty string")


def _require_sha256(value: str, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ContractError(f"{name} must be 64 lowercase hexadecimal characters")


def _reject_json_constant(value: str) -> Any:
    raise ContractError(f"non-finite JSON number is not allowed: {value}")


def _encode_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, JsonContract):
        return {field.name: _encode_value(getattr(value, field.name)) for field in fields(value)}
    if is_dataclass(value):
        return {field.name: _encode_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_encode_value(item) for item in value]
    if isinstance(value, list):
        return [_encode_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _encode_value(item) for key, item in value.items()}
    return value


def _decode_value(annotation: Any, value: Any, path: str) -> Any:
    if annotation is Any:
        return value

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin in (Union, types.UnionType):
        if value is None and type(None) in args:
            return None
        failures: list[str] = []
        for option in args:
            if option is type(None):
                continue
            try:
                return _decode_value(option, value, path)
            except (UnknownFieldError, SchemaVersionError):
                raise
            except (ContractError, TypeError, ValueError) as exc:
                failures.append(str(exc))
        raise ContractError(f"{path} does not match any allowed type: {'; '.join(failures)}")

    if origin is tuple:
        if not isinstance(value, (list, tuple)):
            raise ContractError(f"{path} must be an array")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode_value(args[0], item, f"{path}[]") for item in value)
        if len(value) != len(args):
            raise ContractError(f"{path} must contain exactly {len(args)} items")
        return tuple(
            _decode_value(kind, item, f"{path}[]") for kind, item in zip(args, value, strict=True)
        )

    if origin is list:
        if not isinstance(value, list):
            raise ContractError(f"{path} must be an array")
        return [_decode_value(args[0], item, f"{path}[]") for item in value]

    if origin is dict:
        if not isinstance(value, dict):
            raise ContractError(f"{path} must be an object")
        return {
            _decode_value(args[0], key, f"{path}.key"): _decode_value(
                args[1], item, f"{path}.{key}"
            )
            for key, item in value.items()
        }

    if isinstance(annotation, type) and issubclass(annotation, JsonContract):
        if not isinstance(value, dict):
            raise ContractError(f"{path} must be an object")
        return annotation.from_dict(value)

    if isinstance(annotation, type) and issubclass(annotation, Enum):
        try:
            return annotation(value)
        except (TypeError, ValueError) as exc:
            allowed = ", ".join(repr(member.value) for member in annotation)
            raise ContractError(f"{path} must be one of {allowed}") from exc

    if annotation is bool:
        if type(value) is not bool:
            raise ContractError(f"{path} must be a boolean")
        return value
    if annotation is int:
        if type(value) is not int:
            raise ContractError(f"{path} must be an integer")
        return value
    if annotation is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ContractError(f"{path} must be a number")
        decoded = float(value)
        if not math.isfinite(decoded):
            raise ContractError(f"{path} must be finite")
        return decoded
    if annotation is str:
        if not isinstance(value, str):
            raise ContractError(f"{path} must be a string")
        return value
    if annotation is type(None):
        if value is not None:
            raise ContractError(f"{path} must be null")
        return None
    return value


@dataclass(frozen=True, slots=True, kw_only=True)
class JsonContract:
    """Mixin for strict, versioned JSON dataclasses."""

    schema_version: str = SCHEMA_VERSION
    CURRENT_SCHEMA_VERSION: ClassVar[str] = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != self.CURRENT_SCHEMA_VERSION:
            raise SchemaVersionError(
                f"unsupported schema_version {self.schema_version!r}; "
                f"expected {self.CURRENT_SCHEMA_VERSION!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return _encode_value(self)

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
            separators=None if indent is not None else (",", ":"),
            allow_nan=False,
        )

    @classmethod
    def from_dict(cls: type[TContract], payload: dict[str, Any]) -> TContract:
        if not isinstance(payload, dict):
            raise ContractError(f"{cls.__name__} payload must be an object")
        expected = {field.name for field in fields(cls)}
        unknown = set(payload) - expected
        if unknown:
            raise UnknownFieldError(
                f"unknown field(s) for {cls.__name__}: {', '.join(sorted(unknown))}"
            )
        if "schema_version" not in payload:
            raise SchemaVersionError(f"{cls.__name__} requires schema_version")
        if payload["schema_version"] != cls.CURRENT_SCHEMA_VERSION:
            raise SchemaVersionError(
                f"unsupported schema_version {payload['schema_version']!r}; "
                f"expected {cls.CURRENT_SCHEMA_VERSION!r}"
            )

        missing = [
            field.name
            for field in fields(cls)
            if field.init
            and field.name not in payload
            and field.default is MISSING
            and field.default_factory is MISSING
        ]
        if missing:
            raise ContractError(
                f"missing field(s) for {cls.__name__}: {', '.join(sorted(missing))}"
            )

        hints = get_type_hints(cls)
        values = {
            field.name: _decode_value(hints[field.name], payload[field.name], field.name)
            for field in fields(cls)
            if field.init and field.name in payload
        }
        return cls(**values)

    @classmethod
    def from_json(cls: type[TContract], payload: str) -> TContract:
        try:
            decoded = json.loads(payload, parse_constant=_reject_json_constant)
        except json.JSONDecodeError as exc:
            raise ContractError(f"invalid JSON for {cls.__name__}: {exc.msg}") from exc
        return cls.from_dict(decoded)


def normalize_diff(diff: str) -> str:
    """Return the canonical diff representation used for IDs and persistence."""

    if not isinstance(diff, str):
        raise ContractError("diff must be a string")
    normalized = unicodedata.normalize("NFC", diff.lstrip("\ufeff"))
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def derive_candidate_id(diff: str) -> str:
    return hashlib.sha256(normalize_diff(diff).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class CommandSpec(JsonContract):
    name: str
    argv: tuple[str, ...]
    timeout_seconds: float = 120.0
    required: bool = True
    cwd: str = "."

    def __post_init__(self) -> None:
        super(CommandSpec, self).__post_init__()
        _require_nonempty(self.name, "name")
        if not self.argv or any(not isinstance(item, str) or not item for item in self.argv):
            raise ContractError("argv must contain one or more non-empty strings")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ContractError("timeout_seconds must be finite and greater than zero")
        _require_nonempty(self.cwd, "cwd")


@dataclass(frozen=True, slots=True, kw_only=True)
class CommandResult(JsonContract):
    command: CommandSpec
    verdict: StageVerdict
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    truncated: bool = False
    reason_code: str = ""

    def __post_init__(self) -> None:
        super(CommandResult, self).__post_init__()
        if not math.isfinite(self.duration_seconds) or self.duration_seconds < 0:
            raise ContractError("duration_seconds must be finite and non-negative")


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedHarness(JsonContract):
    root: str
    digest_sha256: str

    def __post_init__(self) -> None:
        super(TrustedHarness, self).__post_init__()
        _require_nonempty(self.root, "root")
        _require_sha256(self.digest_sha256, "digest_sha256")


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidationPlan(JsonContract):
    build_commands: tuple[CommandSpec, ...] = ()
    test_commands: tuple[CommandSpec, ...] = ()
    poc_command: CommandSpec | None = None
    scanner_command: CommandSpec | None = None
    harness: TrustedHarness | None = None
    target_finding: str | None = None

    def __post_init__(self) -> None:
        super(ValidationPlan, self).__post_init__()
        if (
            self.poc_command is not None or self.scanner_command is not None
        ) and self.harness is None:
            raise ContractError("PoC and scanner commands require a trusted harness")
        if self.target_finding is not None:
            _require_nonempty(self.target_finding, "target_finding")


@dataclass(frozen=True, slots=True, kw_only=True)
class VulnTask(JsonContract):
    task_id: str
    cve_id: str | None
    cwe_id: str
    description: str
    repo_path: str
    language: str
    affected_versions: str
    references: tuple[str, ...] = ()
    base_ref: str = "HEAD"

    def __post_init__(self) -> None:
        super(VulnTask, self).__post_init__()
        for name in (
            "task_id",
            "cwe_id",
            "description",
            "repo_path",
            "language",
            "affected_versions",
            "base_ref",
        ):
            _require_nonempty(getattr(self, name), name)
        if self.cve_id is not None:
            _require_nonempty(self.cve_id, "cve_id")
        if any(not isinstance(reference, str) or not reference for reference in self.references):
            raise ContractError("references must contain non-empty strings")


@dataclass(frozen=True, slots=True, kw_only=True)
class EvaluationMetadata(JsonContract):
    task_id: str
    fixing_commit: str | None
    source: str | None = None

    def __post_init__(self) -> None:
        super(EvaluationMetadata, self).__post_init__()
        _require_nonempty(self.task_id, "task_id")
        if self.fixing_commit is not None:
            _require_nonempty(self.fixing_commit, "fixing_commit")
        if self.source is not None:
            _require_nonempty(self.source, "source")


@dataclass(frozen=True, slots=True, kw_only=True)
class CodeLocation(JsonContract):
    file_path: str
    function_name: str | None
    start_line: int
    end_line: int
    confidence: float
    rationale: str

    def __post_init__(self) -> None:
        super(CodeLocation, self).__post_init__()
        _require_nonempty(self.file_path, "file_path")
        if self.function_name is not None:
            _require_nonempty(self.function_name, "function_name")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ContractError("line range must be positive and ordered")
        if not math.isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
            raise ContractError("confidence must be finite and between 0 and 1")
        _require_nonempty(self.rationale, "rationale")


@dataclass(frozen=True, slots=True, kw_only=True)
class LocalizationResult(JsonContract):
    task_id: str
    candidates: tuple[CodeLocation, ...] = ()

    def __post_init__(self) -> None:
        super(LocalizationResult, self).__post_init__()
        _require_nonempty(self.task_id, "task_id")


@dataclass(frozen=True, slots=True, kw_only=True)
class PatchCandidate(JsonContract):
    task_id: str
    diff: str
    target_location: CodeLocation | None = None
    generated_by: str = "static"
    rationale: str = ""
    candidate_id: str = ""

    def __post_init__(self) -> None:
        super(PatchCandidate, self).__post_init__()
        _require_nonempty(self.task_id, "task_id")
        _require_nonempty(self.generated_by, "generated_by")
        canonical = normalize_diff(self.diff)
        if not canonical.strip():
            raise ContractError("diff must not be empty")
        expected = derive_candidate_id(canonical)
        if self.candidate_id and self.candidate_id != expected:
            raise ContractError("candidate_id does not match normalized diff SHA-256")
        object.__setattr__(self, "diff", canonical)
        object.__setattr__(self, "candidate_id", expected)


@dataclass(frozen=True, slots=True, kw_only=True)
class CritiqueResult(JsonContract):
    candidate_id: str
    verdict: CritiqueVerdict
    issues: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(CritiqueResult, self).__post_init__()
        _require_nonempty(self.candidate_id, "candidate_id")
        if any(not isinstance(issue, str) or not issue for issue in self.issues):
            raise ContractError("issues must contain non-empty strings")


@dataclass(frozen=True, slots=True, kw_only=True)
class SnapshotMetadata(JsonContract):
    commit: str
    tree_digest: str
    archive_sha256: str

    def __post_init__(self) -> None:
        super(SnapshotMetadata, self).__post_init__()
        for name in ("commit", "tree_digest", "archive_sha256"):
            _require_nonempty(getattr(self, name), name)


@dataclass(frozen=True, slots=True, kw_only=True)
class StageResult(JsonContract):
    stage: str
    verdict: StageVerdict
    reason_code: str
    message: str = ""
    command_result: CommandResult | None = None
    security_outcome: SecurityOutcome | None = None
    artifacts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(StageResult, self).__post_init__()
        _require_nonempty(self.stage, "stage")
        _require_nonempty(self.reason_code, "reason_code")


@dataclass(frozen=True, slots=True, kw_only=True)
class BaselineResult(JsonContract):
    task_id: str
    snapshot: SnapshotMetadata | None
    stages: tuple[StageResult, ...]
    usable: bool
    summary: str = ""

    def __post_init__(self) -> None:
        super(BaselineResult, self).__post_init__()
        _require_nonempty(self.task_id, "task_id")
        if self.usable and self.snapshot is None:
            raise ContractError("usable baseline requires snapshot metadata")


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidationResult(JsonContract):
    candidate_id: str
    stages: tuple[StageResult, ...]
    overall: OverallVerdict
    summary: str = ""
    snapshot: SnapshotMetadata | None = None

    def __post_init__(self) -> None:
        super(ValidationResult, self).__post_init__()
        _require_nonempty(self.candidate_id, "candidate_id")


@dataclass(frozen=True, slots=True, kw_only=True)
class FailureRecord(JsonContract):
    task_id: str
    candidate_id: str
    overall: OverallVerdict
    reason: str
    poc_detail: str | None = None  # raw PoC stdout for richer generator feedback

    def __post_init__(self) -> None:
        super(FailureRecord, self).__post_init__()
        _require_nonempty(self.task_id, "task_id")
        _require_nonempty(self.candidate_id, "candidate_id")
        _require_nonempty(self.reason, "reason")


@dataclass(frozen=True, slots=True, kw_only=True)
class Budget(JsonContract):
    max_rounds: int = 1
    max_candidates: int = 20
    max_validations: int = 20
    max_model_calls: int = 20
    max_cost_usd: float = 5.0
    max_elapsed_seconds: float = 600.0
    batch_size: int = 1

    def __post_init__(self) -> None:
        super(Budget, self).__post_init__()
        for name in ("max_rounds", "max_candidates", "max_validations", "batch_size"):
            if getattr(self, name) <= 0:
                raise ContractError(f"{name} must be greater than zero")
        if self.max_model_calls < 0:
            raise ContractError("max_model_calls cannot be negative")
        if not math.isfinite(self.max_cost_usd) or self.max_cost_usd < 0:
            raise ContractError("max_cost_usd must be a finite non-negative number")
        if not math.isfinite(self.max_elapsed_seconds) or self.max_elapsed_seconds <= 0:
            raise ContractError("max_elapsed_seconds must be finite and greater than zero")


@dataclass(frozen=True, slots=True, kw_only=True)
class CostSummary(JsonContract):
    """Budget-accounted usage; persistence is a charged reserve, not I/O telemetry."""

    rounds: int = 0
    candidates_seen: int = 0
    candidates_validated: int = 0
    elapsed_seconds: float = 0.0
    persistence_seconds: float = 0.0
    model_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0

    def __post_init__(self) -> None:
        super(CostSummary, self).__post_init__()
        for name in (
            "rounds",
            "candidates_seen",
            "candidates_validated",
            "model_calls",
            "prompt_tokens",
            "completion_tokens",
        ):
            if getattr(self, name) < 0:
                raise ContractError(f"{name} cannot be negative")
        if (
            not math.isfinite(self.elapsed_seconds)
            or not math.isfinite(self.persistence_seconds)
            or self.elapsed_seconds < 0
            or self.persistence_seconds < 0
        ):
            raise ContractError("elapsed durations must be finite and non-negative")
        if self.persistence_seconds > self.elapsed_seconds + 1e-12:
            raise ContractError("persistence_seconds cannot exceed elapsed_seconds")
        if not math.isfinite(self.cost_usd) or self.cost_usd < 0:
            raise ContractError("cost_usd must be finite and non-negative")


@dataclass(frozen=True, slots=True, kw_only=True)
class TraceEvent(JsonContract):
    sequence: int
    event: str
    task_id: str
    candidate_id: str | None = None
    message: str = ""
    attributes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        super(TraceEvent, self).__post_init__()
        if self.sequence < 0:
            raise ContractError("sequence cannot be negative")
        _require_nonempty(self.event, "event")
        _require_nonempty(self.task_id, "task_id")
        if self.candidate_id is not None:
            _require_nonempty(self.candidate_id, "candidate_id")
        if any(
            not key or not isinstance(key, str) or not isinstance(value, str)
            for key, value in self.attributes
        ):
            raise ContractError("attributes must contain non-empty string keys and string values")


@dataclass(frozen=True, slots=True, kw_only=True)
class RepairResult(JsonContract):
    run_id: str
    input_fingerprint: str
    task_id: str
    baseline: BaselineResult | None
    chosen: PatchCandidate | None
    all_candidates: tuple[PatchCandidate, ...]
    validations: tuple[ValidationResult, ...]
    attempts: int
    cost: CostSummary
    trace: tuple[TraceEvent, ...] = ()
    budget: Budget | None = None

    def __post_init__(self) -> None:
        super(RepairResult, self).__post_init__()
        _require_nonempty(self.run_id, "run_id")
        _require_sha256(self.input_fingerprint, "input_fingerprint")
        _require_nonempty(self.task_id, "task_id")
        if self.baseline is not None and self.baseline.task_id != self.task_id:
            raise ContractError("baseline belongs to a different task")
        if self.attempts < 0:
            raise ContractError("attempts cannot be negative")
        if self.chosen is not None and self.chosen.task_id != self.task_id:
            raise ContractError("chosen candidate belongs to a different task")
        if self.chosen is not None and (self.baseline is None or not self.baseline.usable):
            raise ContractError("a chosen candidate requires a usable persisted baseline")
        if any(candidate.task_id != self.task_id for candidate in self.all_candidates):
            raise ContractError("all candidates must belong to the repair task")
