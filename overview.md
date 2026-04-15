# Repository Overview

`Incursa.Quic` is a trace-first QUIC repository. Consumer-facing library code, requirements, verification artifacts, tests, fuzz harnesses, and benchmarks live together so protocol work can be reviewed from requirement to evidence.

## Canonical Surfaces

- [`README.md`](README.md): repository entry point and navigation.
- [`specs/README.md`](specs/README.md): canonical traceability layout.
- [`layout.md`](layout.md): repository structure summary.
- [`authoring.md`](authoring.md): spec and artifact authoring guidance.
- [`artifact-id-policy.json`](artifact-id-policy.json): artifact identifier policy.
- [`schemas/`](schemas/README.md): repository-level schemas.
- [`specs/schemas/`](specs/schemas/README.md): SpecTrace schemas.
- [`quality/`](quality/README.md): testing intent and attestation contracts.

## Working Model

- Canonical requirements, architecture, work items, and verification artifacts live under [`specs/`](specs/README.md).
- Repository-level testing expectations live in [`quality/testing-intent.yaml`](quality/testing-intent.yaml).
- Supporting guidance in the repo root is descriptive; the owning `SPEC-...` artifacts remain authoritative for protocol behavior.
