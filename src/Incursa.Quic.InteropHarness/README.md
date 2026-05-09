# Incursa.Quic.InteropHarness

`Incursa.Quic.InteropHarness` is the companion process project that adapts `Incursa.Quic` to the QUIC interop runner process contract.

## Boundary

- Library-owned: connection runtime, sender and recovery ownership, TLS-facing transport contracts, packet protection lifecycle state, handshake confirmation, timers, path validation, retransmission planning, transport-visible diagnostics, `QuicConnectionEndpointHost`, and packet open/protect helpers.
- Harness-owned: environment parsing, fixed mount-path mapping, testcase dispatch, exit codes, Docker packaging, startup scripts, and the thin `InteropEndpointHost` wrapper.

## Supported Testcases

- `handshake`
- `post-handshake-stream`
- `keyupdate`
- `multiconnect`
- `retry`
- `resumption`
- `transfer`

Unsupported testcases return `127`.
The repo-local interop helper now classifies the broader documented non-HTTP/3 inventory before a testcase reaches this runtime surface, but this project still only executes the supported cells above.
`chacha20` remains inventory-visible but prerequisite-blocked pending CipherSuitesPolicy support. `resumption` is now inventory-green for the runner's TLS session-resumption cell with managed SSLKEYLOGFILE export proof; it does not imply HTTP/3, 0-RTT, anti-replay, or broader resumption API support.
`zerortt` remains inventory-visible but prerequisite-blocked pending live runner proof and harness classification; bounded internal early-data runtime proof is not enough to mark it supported.

## Build Locally

```bash
dotnet build Incursa.Quic.slnx -c Release
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```

## Local Interop Runner Loop

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```
