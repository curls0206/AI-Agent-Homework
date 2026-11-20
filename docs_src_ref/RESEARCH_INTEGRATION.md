# Research Integration Contract

This document defines the reproducibility boundary between this framework repository and an
external experiment or manuscript repository. The framework repository owns reusable runtime
software. The experiment repository owns the scientific claim.

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## 1. Repository boundary

The framework repository contains the `vulnrepair` package, runtime contracts, deterministic
fixtures, tests, CI, security guidance, and the read-only dashboard. It MUST NOT be used as the
canonical store for benchmark corpora, experiment matrices, raw paper results, statistical
notebooks, figures, tables, or manuscript text.

An external experiment repository SHOULD contain at least:

```text
experiments/
  manifests/             immutable run definitions and framework pin
  scenarios/             benchmark inputs, excluding hidden ground truth from runtime prompts
  raw/                   write-once framework outputs
  derived/               normalized tables produced from raw outputs
analysis/                 deterministic analysis code and environment lock
paper/                    manuscript, figures, and tables
```

Raw outputs SHOULD remain immutable after collection. Corrections SHOULD create a new experiment
ID rather than rewriting an existing run.

## 2. Immutable framework pin

Every publishable experiment MUST identify this repository by its canonical URL and a full Git
commit SHA. A branch such as `main`, a pull request ref, a local editable path, or a mutable tag is
not a reproducible pin. A release tag MAY be recorded for readability, but it does not replace the
commit SHA.

Install directly from the pinned commit:

```text
vulnrepair @ git+https://github.com/NTPUNSL-CS/multi-agent-vulnerability-repair-system.git@<40-hex-commit>
```

The experiment manifest MUST preserve both the expected commit and the exact install requirement.
Recommended minimum record:

```json
{
  "framework": {
    "repository": "https://github.com/NTPUNSL-CS/multi-agent-vulnerability-repair-system",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "package_version": "0.3.0",
    "repair_result_schema_version": "1.0",
    "evidence_schema_version": "1.0",
    "install_requirement": "vulnrepair @ git+https://github.com/NTPUNSL-CS/multi-agent-vulnerability-repair-system.git@0123456789abcdef0123456789abcdef01234567"
  }
}
```

The commit in this example is illustrative and MUST be replaced with the commit actually used.

## 3. Provenance capture and preflight

After installation and before the first benchmark task, run:

```text
vulnrepair provenance
```

Save the JSON output with the experiment. When installation used a PEP 610 VCS direct URL, the
output includes the resolved commit. The experiment preflight MUST compare that value with the
manifest's expected commit. A missing commit, malformed commit, or mismatch MUST stop a
publishable run rather than silently falling back to the working tree.

An index or local editable installation can still be used for development, but it is not sufficient
provenance for a published result. The framework intentionally does not infer a commit from the
current directory because that could describe a different or dirty checkout.

The package version and schema versions are separate compatibility axes:

- `framework.version` identifies the software release.
- `contracts.repair_result_schema_version` identifies persisted scenario and result contracts.
- `contracts.evidence_schema_version` identifies PoC and scanner evidence emitted by the trusted
  harness.

Consumers MUST validate all three. A matching package version alone does not establish result
compatibility.

## 4. Machine-readable compatibility metadata

The authoritative metadata file is
[`src/vulnrepair/framework-compatibility.json`](../src/vulnrepair/framework-compatibility.json).
It is shipped inside the wheel and validated by CI against the Python version surface and runtime
schema constants.

External tooling MAY retrieve that file from the same pinned commit before installing the package.
It MUST NOT retrieve metadata from `main` while executing a different pinned commit. Consumers
SHOULD reject unknown `metadata_schema_version` values and SHOULD fail closed when a required
field is absent.

## 5. Runtime input boundary

The experiment repository supplies a versioned scenario containing `VulnTask`, localization
candidates, patch candidates or generator settings, `ValidationPlan`, and `Budget`. The target
`base_ref` resolves to an exact Git commit. The trusted harness lives outside the target repository
and its canonical directory digest is stored in `ValidationPlan`.

Evaluation-only ground truth, including an official fixing commit, MUST NOT enter `VulnTask`, model
prompts, runtime trace, or candidate selection. It MAY be joined later by analysis code after the
framework has published its result.

Container images, benchmark datasets, model identifiers, model/provider configuration, and
analysis environments MUST also use immutable identifiers or cryptographic digests when the
underlying system supports them.

## 6. Runtime output boundary

Each completed run is atomically published as one run directory:

```text
<runs>/<run-id>/
  repair-result.json     canonical typed result
  trace.jsonl            event-oriented convenience view
  chosen.diff            selected diff, empty when no candidate is verified
```

`repair-result.json` is the canonical scientific input. `trace.jsonl` and `chosen.diff` are derived
convenience artifacts. Analysis code MUST parse `repair-result.json` through the matching contract
schema and MUST NOT infer success from the existence or non-emptiness of `chosen.diff` alone.

For every collected run, the experiment repository SHOULD record SHA-256 digests for the scenario,
`repair-result.json`, trusted harness, target commit, container image identity, and relevant model
configuration. The task ID is carried inside `repair-result.json`. Run IDs MUST remain unique and
retries MUST receive new run IDs.

## 7. Compatibility and upgrade policy

Framework releases follow Semantic Versioning. Persisted schemas evolve independently:

- Patch releases MUST preserve documented public runtime behavior and current persisted schemas.
- Minor releases MAY add backward-compatible APIs, verdict fields, commands, or metadata fields.
- Major releases MAY make incompatible framework API changes.
- Any incompatible persisted contract or evidence change MUST increment its own schema version,
  regardless of the package version increment.

An experiment series MUST NOT change the framework commit in place. Upgrading the framework starts
a new experiment revision and requires re-running all conditions intended for direct comparison.
If mixed framework versions are intentionally studied, the framework commit becomes an explicit
experimental factor and MUST be included in every result row.

## 8. Publication checklist

Before treating results as publication evidence, verify that the experiment has a full framework
commit pin, matching saved provenance, schema compatibility, immutable target and container
identities, harness digests, unique run IDs, raw artifact hashes, an environment lock, and a clean
separation between runtime inputs and evaluation-only ground truth. Any failed provenance or
compatibility check should invalidate the run rather than be repaired manually after collection.
