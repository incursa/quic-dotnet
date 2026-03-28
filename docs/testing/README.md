# Testing Docs

This folder is the home for future test documentation and generated test inventory output.

For protocol work, testing is only one part of the proof burden. The repository expects positive coverage, negative coverage, fuzzing scope, and benchmarks for processing or serialization hot paths to be defined and traced.

## Tooling

- The repository uses [`.config/dotnet-tools.json`](../../.config/dotnet-tools.json) for repo-local tools.
- `dotnet-stryker` is available there for mutation testing of the parser and test suite.
- Run `dotnet tool restore` before invoking repo-local tools.

## Current state

- The repository includes scaffold smoke and blocking tests that verify the package and API-baseline files are wired correctly.
- Extend this folder and the test project as the real QUIC implementation lands.

## Quality expectations

- As protocol work lands, add positive and negative tests for each behavior slice, plus fuzz or property coverage for byte-oriented parsers and permanent benchmarks under [`../../benchmarks`](../../benchmarks/README.md) for hot serialization or parsing paths.
- Use [`../requirements-workflow.md`](../requirements-workflow.md) as the ordering guide for when to add gaps, requirements, verification, tests, and benchmarks.
- Record canonical proof outcomes under [`../../specs/verification/quic/`](../../specs/verification/quic/).

## Requirement Tagging

- Tag requirement-linked xUnit tests with `[Trait("Requirement", "REQ-...")]` so the test inventory can map evidence back to canonical requirement IDs.
- Add a category trait such as `[Trait("Category", "Positive")]`, `[Trait("Category", "Negative")]`, or `[Trait("Category", "Fuzz")]` when it helps downstream filtering or coverage checks.
- Keep benchmark suites in [`../../benchmarks`](../../benchmarks/README.md) and cross-link their results from the relevant verification artifact.
