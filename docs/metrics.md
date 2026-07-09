---
title: "Incursa QUIC and HTTP/3 Metrics"
---

# Incursa QUIC and HTTP/3 Metrics

Incursa exposes standard `System.Diagnostics.Metrics` instruments. The library does not add OpenTelemetry package dependencies, exporters, ETW, EventSource, or EventCounters. Collectors can subscribe to the meters by name.

These metrics are diagnostic signals for live behavior and operational visibility. They are not benchmark results and should not be used as a substitute for the BenchmarkDotNet suites under `benchmarks/`.

## Meters

- `Incursa.Quic`
- `Incursa.Quic.Http3`

## QUIC Instruments

| Instrument | Type | Meaning | Tags |
| --- | --- | --- | --- |
| `incursa.quic.connections.started` | Counter | Connection runtime instances started. | `role` |
| `incursa.quic.connections.active` | UpDownCounter | Connection runtime instances currently active. | `role` |
| `incursa.quic.connections.closed` | Counter | Connection runtime instances closed or disposed. | `role`, `close_reason` |
| `incursa.quic.streams.opened` | Counter | QUIC streams opened through the stream facade. | `role`, `direction`, `initiator` |
| `incursa.quic.streams.active` | UpDownCounter | QUIC streams currently active through the stream facade. | `role`, `direction`, `initiator` |
| `incursa.quic.streams.closed` | Counter | QUIC streams disposed through the stream facade. | `role`, `direction`, `initiator` |
| `incursa.quic.datagrams.received` | Counter | UDP datagrams received at the QUIC endpoint socket boundary. | `role` |
| `incursa.quic.datagrams.sent` | Counter | UDP datagrams sent at the QUIC endpoint socket boundary. | `role` |
| `incursa.quic.bytes.received` | Counter | UDP datagram bytes received at the QUIC endpoint socket boundary. | `role` |
| `incursa.quic.bytes.sent` | Counter | UDP datagram bytes sent at the QUIC endpoint socket boundary. | `role` |
| `incursa.quic.packets.dropped` | Counter | Datagrams classified as dropped before connection processing. | `role`, `packet_type` |
| `incursa.quic.flow_control.blocked` | Counter | Runtime attempts to emit DATA_BLOCKED or STREAM_DATA_BLOCKED signals. | `role` |
| `incursa.quic.stream_limit.blocked` | Counter | Runtime attempts to emit STREAMS_BLOCKED signals. | `role`, `direction` |
| `incursa.quic.anti_amplification.blocked` | Counter | Path-validation sends blocked by anti-amplification budget. | `role` |
| `incursa.quic.pto.count` | Counter | Recovery probe timeout expirations. | `role`, `packet_type` |
| `incursa.quic.rtt.ms` | Histogram | Latest RTT samples observed from ACK processing, in milliseconds. | `role` |
| `incursa.quic.buffer_pool.rents` | Counter | Buffers rented through the central QUIC buffer pool wrapper. | `size_bucket` |
| `incursa.quic.buffer_pool.requested_rents` | Counter | Buffer rent requests grouped by requested minimum size before `ArrayPool<byte>` expands the rent. | `requested_size_bucket` |
| `incursa.quic.buffer_pool.returns` | Counter | Buffers returned through the central QUIC buffer pool wrapper. | `size_bucket` |
| `incursa.quic.buffer_pool.bytes.requested` | Counter | Requested minimum bytes for central QUIC buffer pool rents before `ArrayPool<byte>` expands the rent. | `requested_size_bucket` |
| `incursa.quic.buffer_pool.bytes.rented` | Counter | Actual array bytes rented through the central QUIC buffer pool wrapper. | `size_bucket` |
| `incursa.quic.buffer_pool.bytes.returned` | Counter | Actual array bytes returned through the central QUIC buffer pool wrapper. | `size_bucket` |
| `incursa.quic.buffer_pool.outstanding.buffers` | UpDownCounter | Net outstanding buffers observed while the metrics listener is active. | `size_bucket` |
| `incursa.quic.buffer_pool.outstanding.bytes` | UpDownCounter | Net outstanding rented bytes observed while the metrics listener is active. | `size_bucket` |
| `incursa.quic.buffer_pool.oversized_rents` | Counter | Rents where the actual array length is larger than the requested length. | `size_bucket` |

## HTTP/3 Instruments

| Instrument | Type | Meaning | Tags |
| --- | --- | --- | --- |
| `incursa.http3.requests.started` | Counter | HTTP/3 requests started after request headers are available. | `role` |
| `incursa.http3.requests.completed` | Counter | HTTP/3 requests completed with a response status. | `role`, `status_class` |
| `incursa.http3.requests.failed` | Counter | HTTP/3 requests that fail after request handling starts. | `role`, `failure_reason` |
| `incursa.http3.request.duration.ms` | Histogram | Request duration from request start to completion or failure, in milliseconds. | `role` |

## Tag Contract

Metrics only use bounded, low-cardinality tags:

- `role`: `client`, `server`
- `direction`: `bidirectional`, `unidirectional`
- `initiator`: `local`, `remote`
- `packet_type`: `initial`, `handshake`, `1rtt`, `retry`, `version_negotiation`, `unknown`
- `close_reason`: `local`, `remote`, `stateless_reset`, `idle_timeout`, `protocol_violation`, `application`, `version_negotiation`, `disposed`, `unknown`
- `failure_reason`: `canceled`, `quic`, `qpack`, `http3`, `argument`, `exception`
- `status_class`: `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `unknown`
- `size_bucket`: `le_1kb`, `le_4kb`, `le_16kb`, `le_64kb`, `le_256kb`, `gt_256kb`
- `requested_size_bucket`: `le_1kb`, `le_4kb`, `le_16kb`, `le_64kb`, `le_256kb`, `gt_256kb`

The metrics surface must not tag by connection ID, stream ID, endpoint, peer address, URL path, exception message, or raw error text.

## Boundary Notes

The core transport remains qlog-free. Metrics are emitted directly through `System.Diagnostics.Metrics` instruments and do not require an `IQuicDiagnosticsSink`, an `IHttp3DiagnosticsSink`, or any qlog capture helper. When no `MeterListener` or collector is subscribed, hot socket datagram paths check instrument enablement before building tag lists.
