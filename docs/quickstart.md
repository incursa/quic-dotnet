# Quickstart

[`Incursa.Quic`](../src/Incursa.Quic/README.md) is currently a scaffold-only repository. The commands below validate the build and packaging setup that is already in place.

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

- The library project currently builds as an empty packable assembly.
- The test project already contains scaffold smoke and blocking tests that validate the package and public API baseline wiring.
- Versioning and package metadata are defined centrally in the repository root.
