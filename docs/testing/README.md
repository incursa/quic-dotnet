# Testing Docs

This folder is the home for future test documentation and generated test inventory output.

## Tooling

- The repository includes the `incursa.testdocs.cli` local tool in [`.config/dotnet-tools.json`](../../.config/dotnet-tools.json).
- When tests exist, run `dotnet tool restore` and then use the CLI to generate docs for the test inventory.

## Current state

- The repository includes scaffold smoke and blocking tests that verify the package and API-baseline files are wired correctly.
- Extend this folder and the test project as the real QUIC implementation lands.

## Quality expectations

- As protocol work lands, add positive and negative tests for each behavior slice, plus fuzz or property coverage for byte-oriented parsers and benchmarks for hot serialization or parsing paths.
- Use [`../requirements-workflow.md`](../requirements-workflow.md) as the ordering guide for when to add gaps, requirements, verification, tests, and benchmarks.
