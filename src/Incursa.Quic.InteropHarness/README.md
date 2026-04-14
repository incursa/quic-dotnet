# Incursa.Quic.InteropHarness

[`Incursa.Quic.InteropHarness`](../../README.md) is the companion process project that shapes the Incursa QUIC library into the process contract expected by the QUIC interop runner.

## Boundary

- Library-owned: connection runtime, sender and recovery ownership, TLS-facing transport contracts, packet protection lifecycle state, handshake confirmation, timers, path validation, retransmission planning, transport-visible diagnostics, `QuicConnectionEndpointHost`, and the packet open/protect helpers.
- Harness-owned: `ROLE`, `TESTCASE`, `REQUESTS`, `QLOGDIR`, and `SSLKEYLOGFILE` parsing; fixed mount-path mapping; handshake and retry dispatch; supported server-role startup with an empty `REQUESTS` list; exit codes; Docker packaging; the startup script; and the thin `InteropEndpointHost` wrapper.

## Endpoint Host Shell

`InteropEndpointHost` is the narrow harness-owned shell around the library-owned endpoint host. It connects the runtime to a real UDP socket boundary so requirement-home tests can observe ingress, transition, and outbound datagram effects without moving protocol ownership into the harness.

## What it does

- Reads `ROLE`, `TESTCASE`, `REQUESTS`, `QLOGDIR`, and `SSLKEYLOGFILE` from the runner environment.
- Uses the first `REQUESTS` URL to seed the handshake endpoint that the client connects to.
- Lets supported server-role paths start even when the runner leaves `REQUESTS` empty, which matches the runner's local server container contract.
- Maps the fixed container paths used by the runner: `/www`, `/downloads`, and `/certs/cert.pem` plus `/certs/priv.key`.
- Preserves TLS material and diagnostics hooks without claiming end-to-end transport support yet.
- Emits contained qlog JSON files under `QLOGDIR` for supported client and listener bootstrap paths.
- Exercises the library-owned runtime through a real connected UDP socket in requirement-home coverage.
- Routes `handshake` into the managed client/listener bootstrap path and returns `0` when that path completes.
- Routes `post-handshake-stream` into the managed child-process path and returns `0` after the client opens and the server accepts the first application stream.
- Routes `retry` into the narrow one-Retry managed child-process path and returns `0` only after the replayed handshake completes.
- Routes `transfer` into the narrow one-stream `/www` -> `/downloads` child-process path and returns `0` only after byte delivery plus EOF on both sides.
- Returns `127` for unsupported interop test cases instead of faking success.
- Returns `1` for invalid process configuration.

## Current testcase support

Supported:

- `handshake`
- `post-handshake-stream`
- `retry` on the narrow one-Retry child-process contract
- `transfer` on the narrow one-stream `/www` -> `/downloads` child-process contract

Unsupported:

- any other testcase not explicitly implemented

## Build locally

```bash
dotnet build Incursa.Quic.slnx -c Release
docker build -f src/Incursa.Quic.InteropHarness/Dockerfile -t incursa-quic-interop-harness ..
```

## Local interop runner loop

Use the repo-local helper when you want to build the harness image and run the external interop runner locally without changing the runner repository's implementation registry.

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```

By default, the helper runs in `both` mode and replaces the runner's `quic-go` both-role slot. Pass `-LocalRole client` or `-LocalRole server` to exercise the local image on one side only; the helper will then default to the runner's `chrome` or `nginx` slot respectively so the opposite side can stay on established peers such as `quic-go` and `msquic`.
Use `-ImplementationSlot` to override the local-side slot and `-PeerImplementationSlots` to choose the peer implementations.

Each run writes a timestamped bundle under `artifacts/interop-runner/<timestamp>-<slot>/` containing the runner JSON report, Markdown output, stderr, the Docker build log, the runner log directory, and a file tree summary.

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

The `handshake` and `post-handshake-stream` testcases now dispatch into the managed bootstrap path. `retry` now dispatches into the narrow managed one-Retry child-process path. `transfer` now dispatches into the narrow managed active-phase transfer path.

## Stubbed today

- `InteropEndpointHost` is a real shell around the library-owned endpoint host, but it is exercised by requirement-home tests rather than runner-dispatched testcases.
- `QLOGDIR` now emits contained qlog JSON snapshots for the supported public client and listener bootstrap paths.
- `SSLKEYLOGFILE` is recorded as future TLS-provider work and does not emit key logs yet.
