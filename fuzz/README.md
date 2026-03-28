# Incursa.Quic.Fuzz

This project contains the SharpFuzz harness for the QUIC header parser slice.

## Purpose

- Feed arbitrary byte sequences into the parser.
- Fail fast on any unexpected exception.
- Reuse the parser's `Try...` entry points so malformed data is handled as a normal rejection path.

## Build

```bash
dotnet build fuzz/Incursa.Quic.Fuzz.csproj -c Release
```

## Tooling

- Run `dotnet tool restore` from the repo root to make the local `sharpfuzz` command available via the `SharpFuzz.CommandLine` tool package.

## Notes

- The harness currently exercises the packet classifier, long-header parser, short-header parser, and Version Negotiation parser on the same input buffer.
- Input corpus, instrumentation, and runner scripts can be added later without changing the harness contract.
