# Incursa.Quic.InteropHarness

[`Incursa.Quic.InteropHarness`](../../README.md) is the companion process project that shapes the Incursa QUIC library into the process contract expected by the QUIC interop runner.

## Boundary

- Library-owned: connection runtime, sender and recovery ownership, TLS-facing transport contracts, packet protection lifecycle state, handshake confirmation, timers, path validation, retransmission planning, transport-visible diagnostics, `QuicConnectionEndpointHost`, and the packet open/protect helpers.
- Harness-owned: `ROLE`, `TESTCASE`, `REQUESTS`, `QLOGDIR`, and `SSLKEYLOGFILE` parsing; fixed mount-path mapping; handshake dispatch; exit codes; Docker packaging; the startup script; and the thin `InteropEndpointHost` wrapper.

## Endpoint Host Shell

`InteropEndpointHost` is the narrow harness-owned shell around the library-owned endpoint host. It connects the runtime to a real UDP socket boundary so requirement-home tests can observe ingress, transition, and outbound datagram effects without moving protocol ownership into the harness.

## What it does

- Reads `ROLE`, `TESTCASE`, `REQUESTS`, `QLOGDIR`, and `SSLKEYLOGFILE` from the runner environment.
- Uses the first `REQUESTS` URL to seed the handshake endpoint that the client connects to and the server listens on.
- Maps the fixed container paths used by the runner: `/www`, `/downloads`, and `/certs/cert.pem` plus `/certs/priv.key`.
- Preserves TLS material and diagnostics placeholder hooks without claiming end-to-end transport support yet.
- Exercises the library-owned runtime through a real connected UDP socket in requirement-home coverage.
- Routes `handshake` into the managed client/listener bootstrap path and returns `0` when that path completes.
- Routes `post-handshake-stream` into the managed child-process path and returns `0` after the client opens and the server accepts the first application stream.
- Returns `127` for unsupported interop test cases instead of faking success.
- Returns `1` for invalid process configuration.

## Current testcase support

Supported:

- `handshake`
- `post-handshake-stream`

Unsupported:

- `transfer`
- `retry`
- any other testcase not explicitly implemented

## Build locally

```bash
dotnet build Incursa.Quic.slnx -c Release
docker build -f src/Incursa.Quic.InteropHarness/Dockerfile -t incursa-quic-interop-harness .
```

## Run locally

The image expects the QUIC interop runner mount layout and environment variables.

```bash
docker run --rm \
  -e ROLE=server \
  -e TESTCASE=handshake \
  -e REQUESTS=https://127.0.0.1:443/ \
  -v "$(pwd)/www:/www" \
  -v "$(pwd)/downloads:/downloads" \
  -v "$(pwd)/certs:/certs" \
  incursa-quic-interop-harness
```

The `handshake` and `post-handshake-stream` testcases now dispatch into the managed bootstrap path. `transfer` and `retry` still return `127`.

## Stubbed today

- `transfer` and `retry` are recognized interop targets but still unsupported.
- `InteropEndpointHost` is a real shell around the library-owned endpoint host, but it is exercised by requirement-home tests rather than runner-dispatched testcases.
- `QLOGDIR` currently selects a placeholder diagnostics sink rather than real qlog output.
- `SSLKEYLOGFILE` is recorded as future TLS-provider work and does not emit key logs yet.
