# Changelog

All notable framework changes are recorded here. Framework versions follow Semantic Versioning;
persisted contract and harness evidence schemas are versioned independently.

## [0.3.0] - 2026-07-12

### Added

- A framework-only repository boundary for external experiment and manuscript repositories.
- `docs/RESEARCH_INTEGRATION.md`, defining immutable commit pinning and artifact ownership.
- Packaged machine-readable compatibility metadata.
- `vulnrepair provenance`, exposing release, contract, evidence, and PEP 610 installation provenance.
- CI checks that keep package, CLI, schema, and compatibility versions synchronized.

### Compatibility

- `RepairResult` and scenario schema remain `1.0`.
- Trusted harness evidence schema remains `1.0`.
- Secure runner, Oracle, patch policy, persistence, and dashboard semantics are unchanged.

## [0.2.0] - 2026-07-12

### Added

- Read-only local observability dashboard and JSON API.
- Packaged static dashboard assets and dashboard security controls.

## [0.1.0] - 2026-07-10

### Added

- Initial fail-closed generate-and-verify framework, typed contracts, Codex provider, Docker
  isolation gate, auditable run store, and deterministic test fixtures.
