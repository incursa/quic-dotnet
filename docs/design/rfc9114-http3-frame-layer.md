---
title: "RFC 9114 HTTP/3 Frame Layer"
---

# RFC 9114 HTTP/3 Frame Layer

This slice establishes a transport-agnostic HTTP/3 frame layer in `Incursa.Quic.Http3`.

## Covered

- RFC 9114 Section 7.1 frame layout: frame Type, Length, and Payload are encoded as QUIC variable-length integer Type, QUIC variable-length integer Length, and exact payload bytes.
- RFC 9114 Section 7.2 DATA, HEADERS, CANCEL_PUSH, SETTINGS, PUSH_PROMISE, GOAWAY, and MAX_PUSH_ID frame parsing and writing.
- RFC 9114 reserved and unknown frame handling at the frame layer: reserved and unknown frame types are preserved as unknown frames instead of failing the parser.
- Streaming frame parsing across partial buffers, including split frame type, split frame length, and split payload bytes.
- Deterministic malformed-frame reporting through `Http3Exception` with RFC 9114 error codes.

## Deferred

- HTTP/3 stream-type rules and frame placement validation.
- Control-stream lifecycle enforcement.
- SETTINGS semantic validation beyond duplicate identifier rejection and exact payload parsing.
- QPACK integration for HEADERS and PUSH_PROMISE payloads.
- HTTP request/response message sequencing.
- Fuzz and benchmark suites for frame parsing and serialization hot paths.
