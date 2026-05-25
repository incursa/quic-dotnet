# External HTTP/3 Interop Report

This is the checked-in report template for the external HTTP/3 interop harness. Run the harness to generate a current report under `.artifacts/http3-external/<run-id>/report.md`.

## Current Checked-In Matrix

| Target | get-small | get-empty | get-large | multiple-concurrent-get | not-found | many-headers | split-data | request-cancellation | goaway | connection-close-in-flight |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| incursa-client__incursa-server | not run | not run | not run | not run | not run | not run | not run | not run | not run | not run |
| curl__incursa-server | not run | not run | not run | not run | not run | not run | not run | not run | not run | not run |
| aioquic-client__incursa-server | not run | not run | not run | not run | not run | not run | not run | not run | not run | not run |
| quiche-client__incursa-server | not run | not run | not run | not run | not run | not run | not run | not run | not run | not run |
| ngtcp2-client__incursa-server | not run | not run | not run | not run | not run | not run | not run | not run | not run | not run |
| incursa-client__aioquic-server | not run | not run | not run | not run | not run | not run | not run | not run | not run | not run |
| incursa-client__quiche-server | not run | not run | not run | not run | not run | not run | not run | not run | not run | not run |
| incursa-client__ngtcp2-server | not run | not run | not run | not run | not run | not run | not run | not run | not run | not run |

## Commands

Windows:

```powershell
pwsh -NoProfile -File scripts\interop\http3-external\Run-Http3ExternalInterop.ps1
```

Linux/macOS:

```bash
bash scripts/interop/http3-external/run-http3-external-interop.sh
```
