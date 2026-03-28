# Incursa.Quic

[`Incursa.Quic`](../../README.md) is the packable, performance-oriented library root for the Incursa QUIC work. It is where the span-backed QUIC header parser and view types for the version-independent packet-header slice live.

## Install

```bash
dotnet add package Incursa.Quic
```

## Status

- Header parser and view types are present for the first packet-header slice.
- Package metadata, versioning, and packaging are already configured in the repository root.
- Future QUIC implementation code can be added here without changing the surrounding repo structure.
