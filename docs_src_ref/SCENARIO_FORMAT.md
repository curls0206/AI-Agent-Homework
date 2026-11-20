# Scenario format

The `repair` and `validate` CLI commands consume one strict JSON document. Locations are always supplied by the caller. Candidate diffs are supplied for the default static generator; with an LLM generator (`repair --generator ollama` or `ollama-replacement`), the `candidates` array may be empty and the model generates new diffs from the localized immutable Git snapshot. Both paths use the same Oracle, policy, budget, trace, and persistence layers.

Every nested persisted contract needs `"schema_version": "1.0"`. Unknown fields are rejected. `fixing_commit` is not a runtime field and will be rejected if placed in a task.

```json
{
  "schema_version": "1.0",
  "task": {
    "schema_version": "1.0",
    "task_id": "example-cwe-79",
    "cve_id": null,
    "cwe_id": "CWE-79",
    "description": "Unescaped user input reaches an HTML response",
    "repo_path": "C:/absolute/path/to/target-repo",
    "language": "python",
    "affected_versions": "1.0",
    "references": [],
    "base_ref": "vulnerable-commit-or-tag"
  },
  "locations": [
    {
      "schema_version": "1.0",
      "file_path": "app.py",
      "function_name": "render_name",
      "start_line": 10,
      "end_line": 12,
      "confidence": 0.95,
      "rationale": "User-controlled text is interpolated into HTML"
    }
  ],
  "candidates": [
    {
      "schema_version": "1.0",
      "task_id": "example-cwe-79",
      "diff": "diff --git a/app.py b/app.py\n...\n",
      "target_location": null,
      "generated_by": "offline-import",
      "rationale": "Encode at the output boundary"
    }
  ],
  "plan": {
    "schema_version": "1.0",
    "harness": {
      "schema_version": "1.0",
      "root": "C:/absolute/path/to/trusted-harness",
      "digest_sha256": "replace-with-64-lowercase-hex-digest"
    },
    "build_commands": [
      {
        "schema_version": "1.0",
        "name": "compile",
        "argv": ["python", "-m", "py_compile", "app.py"],
        "timeout_seconds": 60,
        "required": true,
        "cwd": "."
      }
    ],
    "test_commands": [],
    "poc_command": {
      "schema_version": "1.0",
      "name": "poc",
      "argv": ["python", "/harness/poc.py"],
      "timeout_seconds": 60,
      "required": true,
      "cwd": "."
    },
    "scanner_command": null,
    "target_finding": null
  },
  "budget": {
    "schema_version": "1.0",
    "max_rounds": 8,
    "max_candidates": 24,
    "max_validations": 20,
    "max_model_calls": 20,
    "max_cost_usd": 5.0,
    "max_elapsed_seconds": 2400,
    "batch_size": 3
  }
}
```

> **Note (repair command):** When using `repair`, the five budget parameters `max_rounds`, `max_candidates`, `max_validations`, `max_elapsed_seconds`, and `batch_size` are controlled by CLI flags and the JSON values are ignored. Only `max_model_calls` and `max_cost_usd` are still read from the scenario JSON. The CLI defaults match the standard research budget above; pass `--max-rounds N` etc. to override on a per-run basis.

Run it inside the Agent container (see the top-level README). Everything the container needs is shared through one mounted directory; the paths inside `scenario.json` (`repo_path`, `harness.root`) must be the **container** paths, e.g. `/work/data/repo` and `/work/data/harness`:

```powershell
# compute the harness digest to put into scenario.json (plan.harness.digest_sha256)
podman run --rm --entrypoint python3 -v "${PWD}\data:/work/data" vulnrepair-agent `
  -c "from vulnrepair import compute_harness_digest; print(compute_harness_digest('/work/data/harness'))"

# repair; the sandbox image is built and selected automatically by the container entrypoint
podman run --rm --privileged --network=host `
  -v vulnrepair-store:/var/lib/containers -v "${PWD}\data:/work/data" -v "${PWD}\out:/out" `
  vulnrepair-agent repair /work/data/scenario.json `
    --harness-dir /work/data/harness --output /out `
    --generator ollama-replacement --ollama-host http://<ollama-host>:11434 --ollama-model llama3.3:70b
```

The shorter way to try the format is `vulnrepair-agent solve cwe79`, which generates a complete example scenario and runs it. The Codex CLI provider needs a locally authenticated CLI on the host and is therefore not available inside the container.

The Podman runner mounts the target snapshot at `/workspace` and the required trusted harness at `/harness` read-only whenever a PoC or scanner is configured. The plan digest must match the external directory, the directory must be disjoint from the target repository, and security commands must reference a regular file below `/harness`. Candidate patches are forbidden from modifying validation assets.

## Evidence protocol

A PoC must exit zero only when the harness itself ran successfully and print one JSON object. On the vulnerable baseline it should report `vulnerable`; after a correct patch it should report `blocked` or `clean`.

```json
{"schema_version":"1.0","harness_ok":true,"outcome":"vulnerable"}
```

A scanner must exit zero when the scanner ran successfully and return stable finding fingerprints. `target_finding` must exist in the baseline list and disappear after patching.

```json
{
  "schema_version": "1.0",
  "harness_ok": true,
  "findings": [{"fingerprint": "CWE-79:app.py:render_name"}]
}
```

Non-zero exit status, timeout, malformed JSON, `harness_ok: false`, or a missing target fingerprint is never interpreted as a successful fix.
