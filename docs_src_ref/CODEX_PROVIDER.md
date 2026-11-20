# Codex CLI provider

`CodexCliClient` implements the framework's `ModelClientProtocol` by invoking an already-authenticated local Codex CLI. It is a generation adapter only. It never decides whether a patch is safe: every returned diff must still pass the patch policy, build, regression tests, and differential security Oracle.

## Supported configuration

The provider accepts an explicit model string. The documented presets are:

| Framework selection | Codex model ID | Reasoning effort |
| --- | --- | --- |
| `--codex-profile gpt-5.5` | `gpt-5.5` | `high` |
| `--codex-profile spark` | `gpt-5.3-codex-spark` | `medium` |

The `spark` label is a short CLI profile name; the provider sends the full `gpt-5.3-codex-spark` model ID. Spark access is account- and rollout-dependent during the research preview. Use repeated `--codex-model` options to create a pool, and `--codex-reasoning-effort` to override the shared effort. Duplicate model IDs are rejected so accounting and attribution stay unambiguous.

## Invocation boundary

The adapter builds a fixed argv and never invokes a shell. The prompt is delivered through stdin rather than the process list. Every call uses an empty temporary working directory, `--sandbox read-only`, `--ephemeral`, `--ignore-user-config`, and `--skip-git-repo-check`. Only the bounded `--output-last-message` file becomes the model response. Standard output is discarded, standard error is bounded, and timeout or cancellation terminates the process tree.

Only environment values needed to locate the executable, operating-system runtime, user home, and Codex authentication state are forwarded. Ambient API-key variables are not forwarded. The generated prompt contains a bounded source window materialized from `VulnTask.base_ref`; dirty files, untracked files, evaluation metadata, and official fixing commits are excluded.

## Budget accounting

`ModelPoolGenerator` reserves a call and an equal share of the remaining USD budget before scheduling each invocation. Since the locally authenticated Codex CLI does not return a stable billable-dollar value, `CodexCliClient.accounting_cost_usd` is an operator-provided conservative charge. The provider refuses to start if this charge exceeds its per-call reservation. A zero charge is valid for subscription-backed experiments, but `Budget.max_model_calls` still bounds total invocations.

## Python API

```python
from vulnrepair import CodexCliClient, GitSnapshotContextProvider, ModelPoolGenerator

generator = ModelPoolGenerator(
    clients=(
        CodexCliClient(model_id="gpt-5.5", reasoning_effort="high"),
        CodexCliClient(model_id="gpt-5.3-codex-spark", reasoning_effort="medium"),
    ),
    context_provider=GitSnapshotContextProvider(),
)
```
