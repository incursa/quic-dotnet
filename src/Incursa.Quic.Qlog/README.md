# Incursa.Quic.Qlog

`Incursa.Quic.Qlog` is the sibling QUIC diagnostics adapter package for `Incursa.Quic`.

## What It Covers

- typed mapping from `Incursa.Quic` transport diagnostics into `Incursa.Qlog.Quic`
- per-connection qlog trace collection without file or serializer ownership
- a narrow host-facing capture helper that can collect traces in memory and serialize contained JSON above the adapter boundary
- qlog draft schema registration at the adapter boundary

## Notes

- The transport core remains qlog-free.
- The adapter stays focused on event mapping and trace append behavior.
- Serializer choice and file output remain above this layer.
- Contained JSON serialization is available above the adapter through the host-facing capture helper.
