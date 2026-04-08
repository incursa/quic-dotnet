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
- New protocol proof should live in a requirement-home file under `tests/Incursa.Quic.Tests/RequirementHomes/<RFC>/REQ-....cs`, not in a broad root test class. If an existing root test class still carries proof, split the proof into smaller requirement-home files and retire the root class once it only contains helper code or disappears entirely.
- The repository docs in [`docs/testing`](../../docs/testing/README.md) and [`docs/requirements-workflow.md`](../../docs/requirements-workflow.md) describe how to expand the test workflow as the implementation grows.
