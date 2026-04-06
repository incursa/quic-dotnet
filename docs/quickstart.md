# Quickstart

[`Incursa.Quic`](../src/Incursa.Quic/README.md) is a trace-first repository with live QUIC helper surfaces. The commands below validate the build and packaging setup that is already in place.

## Restore and build

```bash
dotnet tool restore
dotnet restore Incursa.Quic.slnx
dotnet build Incursa.Quic.slnx -c Release
dotnet test Incursa.Quic.slnx -c Release
```

## Pack the library

```bash
dotnet pack src/Incursa.Quic/Incursa.Quic.csproj -c Release
```

## What to expect

- The library project currently builds as a packable assembly with the existing helper surface.
- The test project already contains smoke and blocking tests that validate the package and public API baseline wiring, plus the broader requirement-tagged suite used by the quality attestation path.
- Versioning and package metadata are defined centrally in the repository root.
