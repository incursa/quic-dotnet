# Incursa.Quic.InteropHarness

[`Incursa.Quic.InteropHarness`](../../README.md) is the companion process project that shapes the Incursa QUIC library into the process contract expected by the QUIC interop runner.

## Boundary

- Library-owned: connection runtime, sender and recovery ownership, TLS-facing transport contracts, packet protection lifecycle state, handshake confirmation, timers, path validation, retransmission planning, and transport-visible diagnostics.
- Harness-owned: `ROLE`, `TESTCASE`, `REQUESTS`, `QLOGDIR`, and `SSLKEYLOGFILE` parsing; fixed mount-path mapping; client or server dispatch; exit codes; Docker packaging; and the startup script.

## What it does

- Reads `ROLE`, `TESTCASE`, `REQUESTS`, `QLOGDIR`, and `SSLKEYLOGFILE` from the runner environment.
- Maps the fixed container paths used by the runner: `/www`, `/downloads`, and `/certs/cert.pem` plus `/certs/priv.key`.
- Preserves TLS material and diagnostics placeholder hooks without claiming end-to-end transport support yet.
- Returns `127` for unsupported interop test cases instead of faking success.
- Returns `1` for invalid process configuration.

## Current testcase support

Supported:

- none yet

Unsupported:

- `handshake`
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
  -v "$(pwd)/www:/www" \
  -v "$(pwd)/downloads:/downloads" \
  -v "$(pwd)/certs:/certs" \
  incursa-quic-interop-harness
```

The current build returns `127` for the QUIC test cases above because the library still owns the real transport behavior and the harness is only the adapter layer.

## Stubbed today

- `handshake`, `transfer`, and `retry` are recognized interop targets but still unsupported.
- `QLOGDIR` currently selects a placeholder diagnostics sink rather than real qlog output.
- `SSLKEYLOGFILE` is recorded as future TLS-provider work and does not emit key logs yet.
