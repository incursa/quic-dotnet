# Incursa.Quic.Tests

[`Incursa.Quic.Tests`](../../README.md) is the xUnit project for the Incursa QUIC implementation slices.

## Install and run

```bash
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj
```

## Status

- The project is wired for xUnit, coverage collection, and future test-doc generation.
- The current slice includes requirement-tagged packet-header tests, deterministic fuzz-style coverage, FsCheck-backed property coverage, and baseline smoke tests.
- Ordinary unit and integration tests are necessary but not sufficient for protocol slices that parse, encode, decode, serialize, or otherwise transform wire data.
- Requirement-linked xUnit cases should use `Trait("Requirement", "REQ-...")` so inventory tooling can map evidence back to canonical requirement IDs.
- Add a category trait such as `Positive`, `Negative`, `Property`, or `Fuzz` when it helps downstream filtering or coverage checks.
- The repository docs in [`docs/testing`](../../docs/testing/README.md) and [`docs/requirements-workflow.md`](../../docs/requirements-workflow.md) describe how to expand the test workflow as the implementation grows.
