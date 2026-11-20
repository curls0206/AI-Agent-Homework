"""Command-line interface for offline repair scenarios."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ._version import __version__
from .adapters import InMemoryRepairMemory, PolicyCritic, StaticGenerator, StaticLocalizer
from .codex import CodexCliClient
from .contracts import (
    SCHEMA_VERSION,
    Budget,
    CodeLocation,
    ContractError,
    PatchCandidate,
    RepairResult,
    ValidationPlan,
    VulnTask,
)
from .course_fixtures import fixture_names, write_fixture
from .demo import demo_scenario
from .models import GitSnapshotContextProvider, ModelPoolGenerator
from .ollama_client import OllamaModelClient, OllamaReplacementClient
from .ollama_localizer import OllamaLocalizer
from .oracle import VerificationOracle
from .orchestrator import RepairOrchestrator
from .ports import GeneratorProtocol, LocalizerProtocol
from .provenance import get_framework_provenance
from .runners import DockerCommandRunner, LocalCommandRunner, PodmanCommandRunner
from .store import JsonRunStore
from .trace_view import render_react_trace


@dataclass(frozen=True, slots=True)
class Scenario:
    task: VulnTask
    locations: tuple[CodeLocation, ...]
    candidates: tuple[PatchCandidate, ...]
    plan: ValidationPlan
    budget: Budget


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnrepair",
        description="Deterministic generate-and-verify framework for security patches.",
    )
    parser.add_argument("--version", action="version", version=f"vulnrepair {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="run the built-in offline CWE-79 fixture")
    demo.add_argument("--output", type=Path, default=Path("runs"), help="run artifact root")
    demo.add_argument(
        "--runner",
        choices=("podman", "docker", "local"),
        default="podman",
        help="Podman is the default sandbox; local is only for the trusted demo fixture",
    )
    demo.add_argument("--image", help="immutable sha256 image ID of the sandbox image")
    demo.add_argument(
        "--allow-unsafe-local-exec",
        action="store_true",
        help="required acknowledgement when --runner local is selected",
    )

    repair = subparsers.add_parser("repair", help="run all candidates in a scenario JSON file")
    repair.add_argument("scenario", type=Path)
    _add_runner_arguments(repair)
    _add_budget_arguments(repair)
    _add_localizer_arguments(repair)
    _add_generator_arguments(repair)

    validate = subparsers.add_parser("validate", help="validate one candidate from a scenario")
    validate.add_argument("scenario", type=Path)
    validate.add_argument("candidate_id", help="content-derived SHA-256 candidate ID")
    _add_runner_arguments(validate)

    show = subparsers.add_parser("show-run", help="read a persisted run directory")
    show.add_argument("run_dir", type=Path)

    trace = subparsers.add_parser(
        "show-trace", help="print a run's Decision / Action / Observation trace"
    )
    trace.add_argument("run_dir", type=Path)

    fixture = subparsers.add_parser(
        "fixture", help="create a small vulnerable app + harness + scenario.json"
    )
    fixture.add_argument("name", choices=fixture_names())
    fixture.add_argument("--out", type=Path, default=Path("fixtures"), help="output directory")
    fixture.add_argument(
        "--mode",
        choices=("located", "zero"),
        default="located",
        help="located: scenario carries the WHERE location; zero: no location hints",
    )

    subparsers.add_parser(
        "provenance",
        help="print machine-readable framework and installation provenance",
    )

    dashboard = subparsers.add_parser(
        "dashboard",
        help="serve the read-only run observability dashboard",
    )
    dashboard.add_argument(
        "--runs",
        type=Path,
        default=Path("runs"),
        help="run artifact root to observe",
    )
    dashboard.add_argument("--host", default="127.0.0.1", help="listen address")
    dashboard.add_argument("--port", type=int, default=8765, help="listen port")
    dashboard.add_argument(
        "--allow-remote",
        action="store_true",
        help="explicitly allow binding to a non-loopback address",
    )
    return parser


def _add_runner_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, default=Path("runs"), help="run artifact root")
    parser.add_argument(
        "--runner",
        choices=("podman", "docker", "local"),
        default="podman",
        help="Podman is the default sandbox; local is only for trusted fixtures",
    )
    parser.add_argument("--image", help="digest-pinned container image or immutable sha256 image ID")
    parser.add_argument(
        "--harness-dir", type=Path, help="trusted harness mounted read-only at /harness"
    )
    parser.add_argument(
        "--allow-unsafe-local-exec",
        action="store_true",
        help="required when --runner local is selected",
    )


def _add_localizer_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--localizer",
        choices=("static", "ollama"),
        default="static",
        help=(
            "static: use locations from the scenario JSON (default); "
            "ollama: let an LLM read the repo and find the vulnerability itself"
        ),
    )


def _add_budget_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-rounds", type=int, default=8, metavar="N",
        help="maximum repair rounds (default: 8)",
    )
    parser.add_argument(
        "--max-candidates", type=int, default=24, metavar="N",
        help="maximum candidates to generate in total (default: 24)",
    )
    parser.add_argument(
        "--max-validations", type=int, default=20, metavar="N",
        help="maximum candidates to send to the verification oracle (default: 20)",
    )
    parser.add_argument(
        "--max-elapsed-seconds", type=float, default=2400.0, metavar="S",
        help="wall-clock time limit in seconds (default: 2400)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=3, metavar="N",
        help="candidates generated per round (default: 3)",
    )


def _add_generator_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--generator",
        choices=("static", "codex", "ollama", "ollama-replacement"),
        default="static",
        help=(
            "use scenario candidates, local Codex CLI, or a remote Ollama server; "
            "ollama-replacement asks for old→new JSON and builds the diff internally"
        ),
    )
    parser.add_argument(
        "--ollama-host",
        default="http://localhost:11434",
        help="Ollama server base URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--ollama-model",
        action="append",
        dest="ollama_model",
        help="Ollama model ID; repeat for a diverse model pool",
    )
    parser.add_argument(
        "--ollama-samples-per-model",
        type=int,
        default=1,
        help="candidate attempts per model and localized source location",
    )
    parser.add_argument(
        "--ollama-timeout-seconds",
        type=float,
        default=300.0,
        help="HTTP timeout per Ollama request in seconds",
    )
    parser.add_argument(
        "--ollama-api-key",
        default="",
        help="Bearer token for Ollama servers with OLLAMA_API_KEY auth",
    )
    parser.add_argument(
        "--codex-profile",
        choices=("gpt-5.5", "spark"),
        default="gpt-5.5",
        help=("Codex-Spark profile maps to gpt-5.3-codex-spark with medium reasoning"),
    )
    parser.add_argument(
        "--codex-model",
        action="append",
        help="Codex model ID; repeat to build a diverse model pool (overrides --codex-profile)",
    )
    parser.add_argument(
        "--codex-reasoning-effort",
        choices=("low", "medium", "high", "xhigh"),
        help="override the selected profile's reasoning effort",
    )
    parser.add_argument(
        "--codex-samples-per-model",
        type=int,
        default=1,
        help="candidate attempts per model and localized source location",
    )
    parser.add_argument(
        "--codex-timeout-seconds",
        type=float,
        default=120.0,
        help="deadline for each Codex CLI invocation",
    )
    parser.add_argument(
        "--codex-accounting-cost-usd",
        type=float,
        default=0.0,
        help="conservative per-call cost charged against Budget.max_cost_usd",
    )
    parser.add_argument(
        "--codex-executable",
        help="absolute path to the Codex CLI; otherwise resolve codex from PATH",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if getattr(arguments, "image", "unset") is None:
        arguments.image = os.environ.get("VULNREPAIR_SANDBOX_IMAGE") or None
    try:
        if arguments.command == "demo":
            if arguments.runner == "local" and not arguments.allow_unsafe_local_exec:
                parser.error("demo --runner local requires --allow-unsafe-local-exec")
            if arguments.runner != "local" and not arguments.image:
                parser.error(f"demo --runner {arguments.runner} requires --image")
            return asyncio.run(_run_demo(arguments))
        if arguments.command == "show-run":
            return asyncio.run(_show_run(arguments.run_dir))
        if arguments.command == "show-trace":
            return asyncio.run(_show_trace(arguments.run_dir))
        if arguments.command == "fixture":
            print(write_fixture(arguments.name, arguments.out, mode=arguments.mode))
            return 0
        if arguments.command == "provenance":
            print(json.dumps(get_framework_provenance(), indent=2, sort_keys=True))
            return 0
        if arguments.command == "dashboard":
            from .dashboard import serve_dashboard

            try:
                serve_dashboard(
                    arguments.runs,
                    host=arguments.host,
                    port=arguments.port,
                    allow_remote=arguments.allow_remote,
                )
            except KeyboardInterrupt:
                return 0
            return 0
        scenario = load_scenario(arguments.scenario)
        if arguments.command == "repair":
            cli_budget = Budget(
                max_rounds=arguments.max_rounds,
                max_candidates=arguments.max_candidates,
                max_validations=arguments.max_validations,
                max_model_calls=scenario.budget.max_model_calls,
                max_cost_usd=scenario.budget.max_cost_usd,
                max_elapsed_seconds=arguments.max_elapsed_seconds,
                batch_size=arguments.batch_size,
            )
            scenario = Scenario(
                task=scenario.task,
                locations=scenario.locations,
                candidates=scenario.candidates,
                plan=scenario.plan,
                budget=cli_budget,
            )
        if arguments.command == "validate":
            matches = tuple(
                candidate
                for candidate in scenario.candidates
                if candidate.candidate_id == arguments.candidate_id
            )
            if not matches:
                raise ContractError(f"candidate not found: {arguments.candidate_id}")
            scenario = Scenario(
                task=scenario.task,
                locations=scenario.locations,
                candidates=matches,
                plan=scenario.plan,
                budget=Budget(
                    max_rounds=1,
                    max_candidates=1,
                    max_validations=1,
                    max_model_calls=scenario.budget.max_model_calls,
                    max_cost_usd=scenario.budget.max_cost_usd,
                    max_elapsed_seconds=scenario.budget.max_elapsed_seconds,
                    batch_size=1,
                ),
            )
        runner = _make_runner(arguments)
        localizer = _make_localizer(arguments, scenario)
        generator = _make_generator(arguments, scenario)
        return asyncio.run(_run_scenario(scenario, runner, arguments.output, generator, localizer))
    except (
        ContractError,
        FileNotFoundError,
        OSError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _make_localizer(
    arguments: argparse.Namespace, scenario: Scenario
) -> LocalizerProtocol:
    localizer_choice = getattr(arguments, "localizer", "static")
    if localizer_choice == "ollama":
        model_ids = tuple(getattr(arguments, "ollama_model", None) or ())
        if not model_ids:
            raise ValueError("--localizer ollama requires at least one --ollama-model")
        base_url: str = getattr(arguments, "ollama_host", "http://localhost:11434")
        timeout: float = getattr(arguments, "ollama_timeout_seconds", 300.0)
        api_key: str = getattr(arguments, "ollama_api_key", "")
        return OllamaLocalizer(
            model_id=model_ids[0],
            base_url=base_url,
            timeout_seconds=timeout,
            api_key=api_key,
        )
    return StaticLocalizer(scenario.locations)


def _make_runner(arguments: argparse.Namespace) -> LocalCommandRunner | DockerCommandRunner:
    if arguments.runner == "local":
        if not arguments.allow_unsafe_local_exec:
            raise ValueError("local runner requires --allow-unsafe-local-exec")
        return LocalCommandRunner(allow_unsafe=True)
    if not arguments.image:
        raise ValueError(f"{arguments.runner} runner requires --image with an immutable ID or digest")
    runner_class = PodmanCommandRunner if arguments.runner == "podman" else DockerCommandRunner
    return runner_class(
        image=arguments.image,
        harness_dir=arguments.harness_dir,
    )


def _make_generator(arguments: argparse.Namespace, scenario: Scenario) -> GeneratorProtocol:
    generator = getattr(arguments, "generator", "static")

    if generator == "static":
        return StaticGenerator(scenario.candidates)

    if generator in ("ollama", "ollama-replacement"):
        model_ids = tuple(getattr(arguments, "ollama_model", None) or ("kimi-k2.7-code:cloud",))
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("Ollama model IDs must be unique")
        base_url: str = getattr(arguments, "ollama_host", "http://localhost:11434")
        timeout: float = getattr(arguments, "ollama_timeout_seconds", 300.0)
        api_key: str = getattr(arguments, "ollama_api_key", "")
        client_cls = OllamaReplacementClient if generator == "ollama-replacement" else OllamaModelClient
        clients = tuple(
            client_cls(
                model_id=model_id,
                base_url=base_url,
                timeout_seconds=timeout,
                api_key=api_key,
            )
            for model_id in model_ids
        )
        return ModelPoolGenerator(
            clients=clients,
            context_provider=GitSnapshotContextProvider(),
            samples_per_model=getattr(arguments, "ollama_samples_per_model", 1),
        )

    profiles = {
        "gpt-5.5": ("gpt-5.5", "high"),
        "spark": ("gpt-5.3-codex-spark", "medium"),
    }
    profile_model, profile_effort = profiles[arguments.codex_profile]
    model_ids = tuple(arguments.codex_model or (profile_model,))
    if len(model_ids) != len(set(model_ids)):
        raise ValueError("Codex model IDs must be unique")
    reasoning_effort = arguments.codex_reasoning_effort or profile_effort
    clients = tuple(
        CodexCliClient(
            model_id=model_id,
            reasoning_effort=reasoning_effort,
            executable=arguments.codex_executable,
            timeout_seconds=arguments.codex_timeout_seconds,
            accounting_cost_usd=arguments.codex_accounting_cost_usd,
        )
        for model_id in model_ids
    )
    return ModelPoolGenerator(
        clients=clients,
        context_provider=GitSnapshotContextProvider(),
        samples_per_model=arguments.codex_samples_per_model,
    )


async def _run_demo(arguments: argparse.Namespace) -> int:
    output: Path = arguments.output
    containerized = arguments.runner != "local"
    with demo_scenario(containerized=containerized) as scenario:
        budget = Budget(
            max_rounds=1,
            max_candidates=len(scenario.candidates),
            max_validations=len(scenario.candidates),
            max_elapsed_seconds=120,
            batch_size=len(scenario.candidates),
        )
        result = await _execute(
            Scenario(
                task=scenario.task,
                locations=(scenario.location,),
                candidates=scenario.candidates,
                plan=scenario.plan,
                budget=budget,
            ),
            (
                LocalCommandRunner(allow_unsafe=True)
                if not containerized
                else _make_runner_for(arguments, harness_dir=scenario.harness)
            ),
            output,
        )
    _print_summary(result, output)
    return 0 if result.chosen is not None else 1


def _make_runner_for(
    arguments: argparse.Namespace, *, harness_dir: Path
) -> DockerCommandRunner:
    runner_class = PodmanCommandRunner if arguments.runner == "podman" else DockerCommandRunner
    return runner_class(image=arguments.image, harness_dir=harness_dir)


async def _run_scenario(
    scenario: Scenario,
    runner: LocalCommandRunner | DockerCommandRunner,
    output: Path,
    generator: GeneratorProtocol,
    localizer: LocalizerProtocol | None = None,
) -> int:
    result = await _execute(scenario, runner, output, generator=generator, localizer=localizer)
    _print_summary(result, output)
    return 0 if result.chosen is not None else 1


async def _execute(
    scenario: Scenario,
    runner: LocalCommandRunner | DockerCommandRunner,
    output: Path,
    *,
    generator: GeneratorProtocol | None = None,
    localizer: LocalizerProtocol | None = None,
) -> RepairResult:
    store = JsonRunStore(output)
    orchestrator = RepairOrchestrator(
        localizer=localizer or StaticLocalizer(scenario.locations),
        generator=generator or StaticGenerator(scenario.candidates),
        critic=PolicyCritic(),
        oracle=VerificationOracle(runner),
        memory=InMemoryRepairMemory(),
        budget=scenario.budget,
        store=store,
    )
    return await orchestrator.repair(scenario.task, scenario.plan)


async def _show_run(run_dir: Path) -> int:
    store = JsonRunStore(run_dir.parent)
    result = await store.load(run_dir)
    print(result.to_json())
    return 0


async def _show_trace(run_dir: Path) -> int:
    store = JsonRunStore(run_dir.parent)
    result = await store.load(run_dir)
    print(render_react_trace(result))
    return 0


def _print_summary(result: RepairResult, output: Path) -> None:
    selected = result.chosen.candidate_id if result.chosen is not None else "none"
    print(
        json.dumps(
            {
                "run_id": result.run_id,
                "task_id": result.task_id,
                "chosen": selected,
                "candidates": len(result.all_candidates),
                "validations": len(result.validations),
                "artifact_dir": str((output / result.run_id).resolve()),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def load_scenario(path: Path) -> Scenario:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ContractError("scenario must be a JSON object")
    allowed = {"schema_version", "task", "locations", "candidates", "plan", "budget"}
    unknown = set(payload) - allowed
    if unknown:
        raise ContractError(f"unknown scenario field(s): {', '.join(sorted(unknown))}")
    missing = allowed - set(payload)
    if missing:
        raise ContractError(f"missing scenario field(s): {', '.join(sorted(missing))}")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ContractError(f"unsupported scenario schema: {payload['schema_version']!r}")
    if not isinstance(payload["locations"], list) or not isinstance(payload["candidates"], list):
        raise ContractError("locations and candidates must be arrays")
    return Scenario(
        task=VulnTask.from_dict(payload["task"]),
        locations=tuple(CodeLocation.from_dict(item) for item in payload["locations"]),
        candidates=tuple(PatchCandidate.from_dict(item) for item in payload["candidates"]),
        plan=ValidationPlan.from_dict(payload["plan"]),
        budget=Budget.from_dict(payload["budget"]),
    )


if __name__ == "__main__":
    raise SystemExit(main())
