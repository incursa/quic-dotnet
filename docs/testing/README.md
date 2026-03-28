# Testing Docs

This folder is the home for future test documentation and generated test inventory output.

## Tooling

- The repository includes the `incursa.testdocs.cli` local tool in [`.config/dotnet-tools.json`](../../.config/dotnet-tools.json).
- When tests exist, run `dotnet tool restore` and then use the CLI to generate docs for the test inventory.

## Current state

- The repository includes scaffold smoke and blocking tests that verify the package and API-baseline files are wired correctly.
- Extend this folder and the test project as the real QUIC implementation lands.
