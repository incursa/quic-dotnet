# Repository Overview

This repository is a trace-first scaffold for the Incursa QUIC library.
The canonical spec-trace suite lives under [`specs/requirements/spec-trace/`](specs/requirements/spec-trace/), and the QUIC-specific requirement slice lives under [`specs/requirements/quic/`](specs/requirements/quic/).

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

Root guidance is descriptive only. The owning `SPEC-...` files in `specs/requirements/spec-trace/` remain authoritative.
