# Incursa.Quic.InteropHarness

`Incursa.Quic.InteropHarness` is the companion process project that adapts `Incursa.Quic` to the QUIC interop runner process contract.

## Boundary

- Library-owned: connection runtime, sender and recovery ownership, TLS-facing transport contracts, packet protection lifecycle state, handshake confirmation, timers, path validation, retransmission planning, transport-visible diagnostics, `QuicConnectionEndpointHost`, and packet open/protect helpers.
- Harness-owned: environment parsing, fixed mount-path mapping, testcase dispatch, exit codes, Docker packaging, startup scripts, and the thin `InteropEndpointHost` wrapper.

## Supported Testcases

- `handshake`
- `post-handshake-stream`
- `retry`
- `transfer`

Unsupported testcases return `127`.

## Build Locally

```bash
dotnet build Incursa.Quic.slnx -c Release
docker build -f src/Incursa.Quic.InteropHarness/Dockerfile -t incursa-quic-interop-harness .
```

## Local Interop Runner Loop

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1
```
