# Incursa.Quic

[`Incursa.Quic`](../../README.md) is the packable, performance-oriented library root for the Incursa QUIC helper layer. It contains the span-backed packet/header parser, varint helpers, frame codecs, and the transport helpers that already exist in the tree.

## Install

```bash
dotnet add package Incursa.Quic
```

## Status

- Header parser and view types are present for the first packet-header slice, and the repository now carries helper surfaces for transport parameters, address validation, anti-amplification, path validation, idle timeout, connection close/drain lifecycle, stateless reset, ACK generation, recovery timing, RTT estimation, congestion control, and AEAD usage limits.
- Package metadata, versioning, and packaging are already configured in the repository root.
- Future QUIC implementation code can be added here without changing the surrounding repo structure.
