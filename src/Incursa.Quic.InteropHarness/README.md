# Incursa.Quic.InteropHarness

`Incursa.Quic.InteropHarness` is the companion process project that adapts `Incursa.Quic` to the QUIC interop runner process contract.

## Boundary

- Library-owned: connection runtime, sender and recovery ownership, TLS-facing transport contracts, packet protection lifecycle state, handshake confirmation, timers, path validation, retransmission planning, transport-visible diagnostics, `QuicConnectionEndpointHost`, and packet open/protect helpers.
- Harness-owned: environment parsing, fixed mount-path mapping, testcase dispatch, exit codes, Docker packaging, startup scripts, and the thin `InteropEndpointHost` wrapper.

## Supported Testcases

- `handshake`
- `versionnegotiation`
- `post-handshake-stream`
- `chacha20`
- `keyupdate`
- `multiconnect`
- `retry`
- `resumption`
- `transfer`

Unsupported testcases return `127`.
The repo-local interop helper now classifies the broader documented non-HTTP/3 inventory before a testcase reaches this runtime surface, but this project still only executes the supported cells above.
`versionnegotiation` uses a reserved-version probe path in the harness and is explicitly dispatched here rather than being inferred from inventory plumbing.
`chacha20` is now inventory-green for the runner's ChaCha20-Poly1305 cell after a local quic-go/quic-go runner attempt succeeded under `artifacts/interop-runner/20260513-011027614-both-quic-go/runner-report.json`. `InteropHarnessRunner` routes it through the transfer-backed dispatch path, and the support claim stays limited to that checked runner cell; it does not imply HTTP/3, 0-RTT, anti-replay, or broader API support.
`zerortt` is now supported/executed for the runner's dedicated hosted Linux proof lane. The former first-flight key-share/HelloRetryRequest blocker now has local CRT proof under `REQ-QUIC-CRT-0154`, the server-role harness path now reads HTTP/0.9 request lines in buffered chunks instead of one byte at a time so the proof path does not amplify receive-credit chatter, and hosted run `25777328991` completed successfully with packet-analysis proof (`0-RTT size: 10570`, `1-RTT size: 2379`). That lane stays advisory, but the inventory cell is now supported/executed and it does not imply HTTP/3, anti-replay, or broader 0-RTT/resumption API support.
`connectionmigration` remains inventory-green in the helper and now has a dedicated hosted `connectionmigration-server-proof` lane to refresh live corroboration against `quiche`, with a companion `connectionmigration-server-proof-blocked` lane that keeps `picoquic`, `lsquic`, `ngtcp2`, `neqo`, `quic-go`, `msquic`, and `aioquic` visible; those lanes stay advisory and do not imply `rebind-port` or `rebind-addr` support.

## Build Locally

```bash
dotnet build Incursa.Quic.slnx -c Release
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```

## Local Interop Runner Loop

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```
