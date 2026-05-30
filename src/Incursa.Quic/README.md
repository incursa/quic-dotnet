# Incursa.Quic

`Incursa.Quic` is the packable core QUIC library in this repository.

## Install

```bash
dotnet add package Incursa.Quic
```

## Consumer Surface

- `QuicConnection`
- `QuicListener`
- `QuicStream`
- `QuicConnectionOptions`
- `QuicClientConnectionOptions`
- `QuicServerConnectionOptions`
- `QuicListenerOptions`
- `QuicPeerCertificatePolicy`
- `QuicException`, `QuicError`, `QuicAbortDirection`, and `QuicStreamType`

## Runtime Note

Use `QuicConnection.IsSupported` and `QuicListener.IsSupported` to check whether the managed runtime-backed QUIC surface is available on the current machine.

Repository details and scope notes live at https://github.com/incursa/quic-dotnet.
