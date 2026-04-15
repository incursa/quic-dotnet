# Incursa.Quic.Tests

`Incursa.Quic.Tests` is the xUnit test project for the repository.

## Run

```bash
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj -c Release
```

## Test Structure

- Requirement-linked proofs live under `tests/Incursa.Quic.Tests/RequirementHomes/<RFC>/REQ-....cs`.
- Requirement-linked xUnit cases should use `Trait("Requirement", "REQ-...")` so inventory tooling can map evidence back to canonical requirement IDs.
- Add category markers such as `Positive`, `Negative`, `Property`, or `Fuzz` when they help downstream filtering or coverage checks.
- Ordinary unit and integration tests are necessary but not sufficient for protocol slices that parse, encode, decode, serialize, or otherwise transform wire data.

See [`../../docs/testing/README.md`](../../docs/testing/README.md) and [`../../docs/requirements-workflow.md`](../../docs/requirements-workflow.md) for the broader testing and proof model.
