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
- `QuicResumptionOutcome`
- `QuicResumptionTicket`
- `QuicException`, `QuicError`, `QuicAbortDirection`, and `QuicStreamType`

## Runtime Note

Use `QuicConnection.IsSupported` and `QuicListener.IsSupported` to check whether the managed runtime-backed QUIC surface is available on the current machine.
Resumption is intentionally transport-only: use `QuicClientConnectionOptions.ResumptionTicket`, `QuicConnection.ResumptionOutcome`, and `QuicServerConnectionOptions.EnableResumptionTickets` for the bounded resumption flow, and do not expect a public early-data or 0-RTT toggle.

Repository details and scope notes live at https://github.com/incursa/quic-dotnet.
