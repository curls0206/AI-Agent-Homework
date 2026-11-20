# Architecture

## Goal

VulnRepair is a generate-and-verify framework. Multiple interchangeable agents may generate diverse patch candidates, but deterministic policy and differential validation make the final decision.

This repository is the reusable runtime boundary. Benchmark corpora, experiment matrices, raw
results, statistical analysis, figures, and manuscript sources belong to an external research
repository that pins this framework by an immutable Git commit. The integration and provenance
contract is defined in [RESEARCH_INTEGRATION.md](RESEARCH_INTEGRATION.md).

```text
VulnTask ──► Localizer ──► CodeLocation[]
                               │
                               ▼
                         Generator pool
                               │
                         PatchCandidate[]
                               │
                         policy + Critic
                               │
                               ▼
baseline ─────────────────► Verification Oracle ◄── fresh patched snapshot
                               │
                     typed differential evidence
                               │
                               ▼
                          RepairResult
```

## Trust boundaries

The coordinator, contracts, patch policy, snapshot materializer, verdict classifier, and trusted validation harnesses are inside the trusted computing base. A target repository, generated patch, build scripts, tests, and target program behavior are untrusted. A security harness must be a disjoint external directory whose canonical SHA-256 is embedded in the validation plan. The Oracle checks that digest before baseline work and again immediately before every security phase. It also requires each PoC/scanner command to reference a file from that directory; Podman runners must mount the exact same directory read-only at `/harness`.

The coordinator never evaluates a dirty working tree. It resolves the requested Git revision, rejects symlinks and submodules, materializes a bounded archive into a temporary directory, and records commit and tree digests. The source repository remains unchanged.

Every candidate is parsed and authorized before any target command runs. Strict `git apply --check` is followed by strict `git apply`; there is no fuzzy `patch` fallback.

Target commands run through a `CommandRunner`. The Podman adapter (Docker-CLI compatible) uses a pinned image, non-root identity, no network, a read-only root filesystem, dropped capabilities, `no-new-privileges`, bounded CPU/memory/PIDs/output, and forced container cleanup. The host-local adapter is disabled until explicitly opted in and is only for trusted fixtures.

## Differential verification

The Oracle first establishes a baseline. Build and regression tests must be healthy, and at least one vulnerability-specific harness must positively demonstrate the vulnerable condition. A candidate is then applied to two fresh snapshots: one for build/regression checks and another for security evidence so build scripts and tests cannot rewrite the tree inspected by the PoC or scanner.

Harness process health and semantic result are separate. PoCs and scanners return versioned JSON. A scanner names a stable finding fingerprint; that fingerprint must be present on the baseline and absent after patching.

| Condition | Overall verdict |
| --- | --- |
| Baseline vulnerability reproduced; patch applies; build/tests pass; required security evidence becomes blocked/clean | `verified_fix` |
| Patch fails, regression occurs, or exploit still works | `rejected` |
| Required evidence is absent or cannot establish a differential result | `inconclusive` |
| Runner, harness, snapshot, timeout, or infrastructure fails | `infra_error` |

No candidate is automatically selected unless its verdict is `verified_fix`.

## Determinism and budgets

The orchestrator normalizes, deduplicates, and canonically sorts candidates. It reserves budget before starting a fixed batch, validates in a stable order, and selects only after the batch completes. Verified patches are ranked by changed-file count, changed-line count, and candidate ID. Time and model usage are recorded but never used as an unstable tie-breaker.

Budgets cap rounds, candidates, Oracle validations, model calls, reported USD cost, and wall time. Every external await receives only the remaining wall-time allowance. Call count and cost are reserved before a model batch is scheduled, and each provider call receives an explicit maximum-cost contract. A provider that reports exceeding its reservation invalidates that generated batch. Reaching a budget returns a complete audit trail with `chosen=None` unless a verified candidate was already established; completed verified evidence is preserved even if a later item in the batch times out.

When a store is configured, the orchestrator reserves up to one second (and at most ten percent of the total wall budget) before model or Oracle work consumes the deadline. `CostSummary.persistence_seconds` is this conservative charged wall-budget reserve, not a claim of exact filesystem latency; `elapsed_seconds` includes the charge. The JSON store writes all artifacts to a hidden sibling staging directory and publishes the directory atomically. Cancellation and commit start are serialized by a lock. Cancellation before commit prevents later publication and asynchronously cleans staging. Once the atomic directory commit begins, consistency wins over a microsecond-precise deadline: the caller shields and awaits that short non-cancellable critical section, so it never returns while a complete run can still appear later.

Each invocation gets a unique `run_id`, while a deterministic `input_fingerprint` captures the task, validation plan, candidate set, budget, and resolved baseline snapshot. The JSON store refuses to overwrite an existing run unless a caller explicitly opts in. Persisted results include the full baseline stages so the evidence that authorized a `verified_fix` remains auditable. JSON parsing and serialization reject non-finite numbers and unknown contract fields.

## Read-only observability

The dashboard is an observer outside the repair decision path. It scans only atomically published run directories, parses every manifest through the strict `RepairResult` contract, and exposes a bounded read-only HTTP API plus packaged static assets. It never imports target repositories, runs commands, changes verdicts, or writes artifacts.

The server binds to loopback by default and rejects non-loopback addresses unless the operator explicitly enables remote binding. Responses use a restrictive content security policy, disable MIME sniffing, and prevent API caching. Remote deployments still require an external authenticated reverse proxy because the built-in server intentionally provides no identity or authorization layer.

## Extending agents

Localizers, generators, critics, memory, model clients, runners, Oracles, and run stores are ports. New adapters must satisfy their protocol without importing provider-specific behavior into the deterministic verdict path.

A model-facing task context intentionally omits evaluation metadata. A provider adapter should record model ID, prompt hash, token counts, cost, and latency while avoiding secrets and full unredacted environment data.
