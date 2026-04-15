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
