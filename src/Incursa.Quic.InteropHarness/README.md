# Incursa.Quic.InteropHarness

`Incursa.Quic.InteropHarness` is the companion process project that adapts `Incursa.Quic` to the QUIC interop runner process contract.

## Boundary

- Library-owned: connection runtime, sender and recovery ownership, TLS-facing transport contracts, packet protection lifecycle state, handshake confirmation, timers, path validation, retransmission planning, transport-visible diagnostics, `QuicConnectionEndpointHost`, and packet open/protect helpers.
- Harness-owned: environment parsing, fixed mount-path mapping, testcase dispatch, exit codes, Docker packaging, startup scripts, and the thin `InteropEndpointHost` wrapper.

## Supported Testcases

- `handshake`
- `versionnegotiation`
- `post-handshake-stream`
- `keyupdate`
- `multiconnect`
- `retry`
- `resumption`
- `transfer`

Unsupported testcases return `127`.
The repo-local interop helper now classifies the broader documented non-HTTP/3 inventory before a testcase reaches this runtime surface, but this project still only executes the supported cells above.
`versionnegotiation` uses a reserved-version probe path in the harness and is explicitly dispatched here rather than being inferred from inventory plumbing.
`chacha20` remains inventory-visible but prerequisite-blocked pending CipherSuitesPolicy support. `resumption` is now inventory-green for the runner's TLS session-resumption cell with managed SSLKEYLOGFILE export proof; it does not imply HTTP/3, 0-RTT, anti-replay, or broader resumption API support.
`zerortt` remains inventory-visible but prerequisite-blocked pending full hosted/Linux runner success, client-side 0-RTT request-stream/packet-analysis proof, and harness classification. The former first-flight key-share/HelloRetryRequest blocker now has local CRT proof under `REQ-QUIC-CRT-0154`, and hosted reruns have progressed past that symptom, but hosted run `25617834482` still failed runner packet analysis after managed response/download success because too much traffic used 1-RTT packets (`0-RTT size: 10618`, `1-RTT size: 16499`). The server-role harness path can now enable managed resumption tickets plus server early-data admission for a runner-driven attempt, but that dispatch path, bounded internal early-data runtime proof, local X25519 proof, and partial hosted proof are not enough to mark the inventory cell supported.

## Build Locally

```bash
dotnet build Incursa.Quic.slnx -c Release
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```

## Local Interop Runner Loop

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```
