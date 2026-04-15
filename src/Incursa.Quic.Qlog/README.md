# Incursa.Quic.Qlog

`Incursa.Quic.Qlog` is the qlog capture adapter package for `Incursa.Quic`.

## Install

```bash
dotnet add package Incursa.Quic.Qlog
```

## What It Provides

- `QuicQlogCapture` for collecting qlog traces from client and listener entry points.
- Mapping from `Incursa.Quic` diagnostics into `Incursa.Qlog.Quic`.
- Contained qlog JSON serialization above the transport boundary.

## Design Notes

- The transport core remains qlog-free.
- The adapter stays focused on event mapping, trace capture, and serialization support.
- File ownership and storage choices remain with the caller.
