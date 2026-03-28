# Incursa.Quic.Tests

[`Incursa.Quic.Tests`](../../README.md) is the test project shell for the future Incursa QUIC implementation.

## Install and run

```bash
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj
```

## Status

- The project is wired for xUnit, coverage collection, and future test-doc generation.
- The initial scaffold includes smoke and blocking tests that validate the repository baseline.
- Ordinary unit and integration tests are necessary but not sufficient for protocol slices that parse, encode, decode, serialize, or otherwise transform wire data.
- Requirement-linked xUnit cases should use `Trait("Requirement", "REQ-...")` so inventory tooling can map evidence back to canonical requirement IDs.
- The repository docs in [`docs/testing`](../../docs/testing/README.md) and [`docs/requirements-workflow.md`](../../docs/requirements-workflow.md) describe how to expand the test workflow as the implementation grows.
