# Incursa.Quic.Dns

`Incursa.Quic.Dns` is the DNS over QUIC package over the managed `Incursa.Quic` transport.

## Install

```bash
dotnet add package Incursa.Quic.Dns
```

## Design Notes

- This package owns DoQ ALPN, default port policy, DoQ error codes, and DNS message framing above QUIC streams.
- `DoqClient` maps each query to a fresh client-initiated bidirectional stream.
- `DoqServer` dispatches inbound bidirectional query streams to an `IDoqQueryHandler` and writes responses on the same stream.
- It depends on `Incursa.Quic` for transport connections and streams.
- It must keep DNS and DoQ semantics out of the QUIC transport runtime.
