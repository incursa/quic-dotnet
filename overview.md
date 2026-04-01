# Repository Overview

This repository is a trace-first scaffold for the Incursa QUIC library.
The QUIC-specific requirement slice lives under [`specs/requirements/quic/`](specs/requirements/quic/), and the repository follows the published SpecTrace model schema from [incursa/spec-trace](https://github.com/incursa/spec-trace/raw/refs/heads/main/model/model.schema.json) instead of keeping a checked-in local spec-trace requirement suite.

## Canonical Surfaces

- [`README.md`](README.md): repository entry point and quick navigation
- [`specs/README.md`](specs/README.md): canonical traceability and artifact placement overview
- [`layout.md`](layout.md): repository layout summary
- [`authoring.md`](authoring.md): requirement authoring guidance
- [`artifact-id-policy.json`](artifact-id-policy.json): machine-readable identifier policy
- [`schemas/`](schemas/README.md): JSON schemas for quality and repository config tooling
- [`specs/schemas/`](specs/schemas/README.md): JSON schemas for SpecTrace validation
- [`quality/`](quality/README.md): quality intent and attestation contracts

## Working Model

The repository keeps the canonical documents in `specs/`, the repo-level testing intent in `quality/testing-intent.yaml`, and the repo-level attestation contract in `quality/attestation.yaml`.

Root guidance is descriptive only. The owning `SPEC-...` files in `specs/requirements/quic/` remain authoritative for repository protocol work.
