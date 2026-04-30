# Incursa.Quic.Fuzz

This project contains the SharpFuzz harnesses for wire-facing `Incursa.Quic` parsing code.

## Purpose

- Feed arbitrary byte sequences into parser entry points.
- Fail fast on unexpected exceptions.
- Reuse `Try...` entry points so malformed data is handled as a normal rejection path.
- Exercise varint, stream identifier, STREAM frame, and packet parser paths.

## Build

```bash
dotnet build fuzz/Incursa.Quic.Fuzz.csproj -c Release
```

## Tooling

Run `dotnet tool restore` from the repo root to make the local `sharpfuzz` command available through the `SharpFuzz.CommandLine` tool package.

Instrument the built library dependency, not the harness executable:

```bash
dotnet tool run sharpfuzz -- fuzz/bin/Release/net10.0/Incursa.Quic.dll
```

For a local smoke run after instrumentation, pipe any byte sequence to the harness:

```bash
printf abc | dotnet fuzz/bin/Release/net10.0/Incursa.Quic.Fuzz.dll
```
