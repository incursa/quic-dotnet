# QUIC Interop Runner HTTP/3

This endpoint image supports the QUIC interop runner `http3` testcase through
`Incursa.Quic.InteropHarness`.

## Endpoint Contract

- Image: built from `src/Incursa.Quic.InteropHarness/Dockerfile`.
- Entrypoint: `src/Incursa.Quic.InteropHarness/run_endpoint.sh`.
- Supported testcase: `TESTCASE=http3`.
- Unsupported testcases still return exit code `127` unless already delegated to an existing supported QUIC testcase path.
- Server mode:
  - `ROLE=server`.
  - Listens on UDP port `443`.
  - Loads `/certs/cert.pem` and `/certs/priv.key`.
  - Negotiates ALPN `h3`.
  - Serves HTTP/3 `GET` responses from `/www`.
- Client mode:
  - `ROLE=client`.
  - Reads absolute HTTPS URLs from `REQUESTS`.
  - Negotiates ALPN `h3`.
  - Downloads each response body to the matching relative path under `/downloads`.
  - Exits `0` on success and `1` on failure.

## Local Runner Command

Run the local Incursa endpoint image against itself for the HTTP/3 testcase:

```powershell
pwsh -NoProfile -File scripts/interop/Invoke-QuicInteropRunner.ps1 `
  -RunnerRoot C:\src\quic-interop\quic-interop-runner `
  -LocalRole both `
  -ImplementationSlot quic-go `
  -PeerImplementationSlots quic-go `
  -TestCases http3 `
  -RunnerTimeoutSeconds 240 `
  -ArtifactsRoot .artifacts\interop-runner\http3-local
```

The helper stages the Docker build context, builds `incursa-quic-interop-harness:local`,
patches the local runner slot through `--replace`, preserves the runner JSON and
Markdown reports, and stores logs under the selected artifact root.
