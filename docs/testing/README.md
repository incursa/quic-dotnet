# Testing Docs

This folder holds test documentation and generated test inventory output for the live QUIC helper-layer test suite.

For protocol work, testing is only one part of the proof burden. The repository expects positive coverage, negative coverage, property-based coverage, fuzzing scope, mutation evidence, and benchmarks for processing or serialization hot paths to be defined and traced.

## Tooling

- The repository uses [`.config/dotnet-tools.json`](../../.config/dotnet-tools.json) for repo-local tools.
- `dotnet-stryker` is available there for mutation testing of the parser and test suite.
- `SharpFuzz.CommandLine` is available there for fuzz harness instrumentation around wire-facing parsers and boundary code.
- Run `dotnet tool restore` before invoking repo-local tools.
- Stryker configuration lives beside the xUnit project in [`../../tests/Incursa.Quic.Tests/stryker-config.json`](../../tests/Incursa.Quic.Tests/stryker-config.json).

## Current state

- The repository includes smoke and blocking tests that verify the package and API-baseline files are wired correctly, plus a broader requirement-tagged xUnit suite that the quality attestation wrapper now runs.
- Extend this folder and the test project as the real QUIC implementation lands.

## Quality expectations

- As protocol work lands, add positive and negative tests for each behavior slice, plus FsCheck-backed property coverage for byte-oriented parsers, fuzz harnesses for wire-facing code, and permanent benchmarks under [`../../benchmarks/README.md`](../../benchmarks/README.md) for hot serialization or parsing paths.
- Use [`../requirements-workflow.md`](../requirements-workflow.md) as the ordering guide for when to add gaps, requirements, verification, tests, and benchmarks.
- Record canonical proof outcomes under [`../../specs/verification/quic/README.md`](../../specs/verification/quic/README.md).

## Requirement Tagging

- Tag requirement-linked xUnit tests with `[Trait("Requirement", "REQ-...")]` so the test inventory can map evidence back to canonical requirement IDs.
- Add a category trait such as `[CoverageType(RequirementCoverageType.Positive)]`, `[CoverageType(RequirementCoverageType.Negative)]`, `[Trait("Category", "Property")]`, or `[Trait("Category", "Fuzz")]` when it helps downstream filtering or coverage checks.
- Keep benchmark suites in [`../../benchmarks/README.md`](../../benchmarks/README.md) and cross-link their results from the relevant verification artifact.
