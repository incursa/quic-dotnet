# Repository Layout

This page summarizes the stable repository layout used by the spec-trace and quality workflows.

## Top-Level Areas

- [`specs/`](specs/README.md): canonical requirements, architecture, work items, verification artifacts, and generated outputs
- [`schemas/`](schemas): machine-readable quality and repository config schemas
- [`specs/schemas/`](specs/schemas/README.md): machine-readable SpecTrace schemas
- [`quality/`](quality/README.md): repo-level testing intent and attestation configuration
- [`docs/`](docs/README.md): repo guidance and workflow notes
- [`scripts/`](scripts/README.md): automation entry points
- [`scripts/spec-trace/`](scripts/spec-trace/README.md): JSON validation, migration, backup, and parity helpers
- [`benchmarks/`](benchmarks/README.md): permanent benchmark suites
- [`fuzz/`](fuzz/README.md): fuzz harnesses
- [`src/Incursa.Quic/`](src/Incursa.Quic/README.md): the packable library project
- [`tests/Incursa.Quic.Tests/`](tests/Incursa.Quic.Tests/README.md): the test project
- [`artifacts/`](artifacts): generated outputs and local migration backups only

## Specs Tree

- [`specs/requirements/quic/`](specs/requirements/quic/): QUIC requirement slices
- [`specs/architecture/quic/`](specs/architecture/quic/): QUIC design artifacts
- [`specs/work-items/quic/`](specs/work-items/quic/): QUIC work items
- [`specs/verification/quic/`](specs/verification/quic/): QUIC verification artifacts
- [`specs/generated/quic/`](specs/generated/quic): QUIC-derived review outputs
- [`specs/templates/`](specs/templates/README.md): copy-ready canonical JSON templates
- [`specs/schemas/`](specs/schemas/README.md): canonical SpecTrace schemas

## Placement Rules

- Keep canonical source artifacts in `specs/`, `specs/schemas/`, and `schemas/`.
- For canonical spec-trace families, author `.json` files and keep workflow references pointed at those `.json` artifacts.
- Keep generated output in `artifacts/` or `specs/generated/`.
- Keep root guidance subordinate to the spec-trace suite.
