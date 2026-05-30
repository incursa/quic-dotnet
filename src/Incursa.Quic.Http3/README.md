# Incursa.Quic.Http3

`Incursa.Quic.Http3` is the HTTP/3 package over the managed `Incursa.Quic` transport.

## Install

```bash
dotnet add package Incursa.Quic.Http3
```

## Design Notes

- This package owns HTTP/3 connection, control-stream, request-stream, SETTINGS, and GOAWAY behavior.
- It depends on `Incursa.Quic` for transport streams and on `Incursa.Qpack` for header compression.
- It must stay independent from ASP.NET hosting concerns.
- A fuller readiness note lives in the repository at https://github.com/incursa/quic-dotnet/blob/main/src/Incursa.Quic.Http3/HTTP3-READINESS.md.
