---
title: "External HTTP/3 Interop Report"
---

# External HTTP/3 Interop Report

This is the checked-in report template for the external HTTP/3 interop harness. Run the harness to generate a current report under `.artifacts/http3-external/<run-id>/report.md`.

Last refreshed from local Docker evidence on 2026-06-19.

- Focused curl/quiche/ngtcp2 client run: `.artifacts/http3-external/20260619T125600Z`
- Focused empty/split-data breadth run: `.artifacts/http3-external/20260619T130112Z`
- Focused quiche/ngtcp2 server run: `.artifacts/http3-external/20260619T124926Z`
- Focused ngtcp2 server qlog-startup rerun: `.artifacts/http3-external/20260619T130437Z`
- Focused ngtcp2 server RFC 9287 greased fixed-bit rerun: `.artifacts/http3-external/20260619T184808Z`
- Focused quiche server large-response row: `.artifacts/http3-external/20260619T125037Z`
- Focused pinned aioquic static GET-style run: `.artifacts/http3-external/20260619T055801Z`
- Plan-only normalized matrix run: `.artifacts/http3-external/20260619T055646Z`
- The focused 2026-06-19 runs record Docker `29.3.0`, Docker Compose `v5.1.0`, `aioquic` pinned to `1.3.0`, and resolved image IDs/digests plus roles, supported scenarios, command templates, and known limitations in `peer-tool-manifest.json`.

- Default matrix run: `.artifacts/http3-default-with-aioquic-server/20260526T042753Z`
- Focused Incursa advanced run: `.artifacts/http3-all-advanced-default/20260526T033718Z`
- Focused aioquic static GET-style run: `.artifacts/http3-aioquic-after-huffman2/20260526T040811Z`
- Focused Incursa client to aioquic server run: `.artifacts/http3-incursa-client-aioquic-server2/20260526T042526Z`
- Incursa proof: `incursa-client__incursa-server` passes all ten configured scenarios.
- External-provider proof: `aioquic-client__incursa-server` and `incursa-client__aioquic-server` pass their executable static GET-style scenarios.

## Current Checked-In Matrix

| Target | get-small | get-empty | get-large | multiple-concurrent-get | not-found | many-headers | split-data | request-cancellation | goaway | connection-close-in-flight |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| incursa-client__incursa-server | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| curl__incursa-server | pass | pass | pass | skip | pass | pass | pass | skip | skip | skip |
| aioquic-client__incursa-server | pass | pass | pass | skip | pass | pass | pass | skip | skip | skip |
| quiche-client__incursa-server | pass | pass | pass | skip | pass | pass | pass | skip | skip | skip |
| ngtcp2-client__incursa-server | pass | pass | pass | skip | pass | pass | pass | skip | skip | skip |
| incursa-client__aioquic-server | pass | pass | pass | skip | pass | pass | pass | skip | skip | skip |
| incursa-client__quiche-server | pass | pass | pass | skip | pass | skip | skip | skip | skip | skip |
| incursa-client__ngtcp2-server | pass | pass | pass | skip | pass | skip | skip | skip | skip | skip |

## Current Findings

- `incursa-client__incursa-server` passes `get-small`, `get-empty`, `get-large`, `multiple-concurrent-get`, `not-found`, `many-headers`, `split-data`, `request-cancellation`, `goaway`, and `connection-close-in-flight` in Docker with qlog capture and preserved stdout/stderr.
- Latest default matrix result: `22 pass`, `0 fail`, `58 skip`.
- Latest focused pinned aioquic static subset result: `6 pass`, `0 fail`, `0 skip` across `incursa-client__incursa-server`, `aioquic-client__incursa-server`, and `incursa-client__aioquic-server` for `get-small` and `not-found`.
- Latest focused external-client subset result: `12 pass`, `0 fail`, `0 skip` across `curl__incursa-server`, `quiche-client__incursa-server`, and `ngtcp2-client__incursa-server` for `get-small`, `not-found`, `get-large`, and `many-headers`.
- Latest focused empty/split-data breadth result: `7 pass`, `0 fail`, `1 skip`; curl, quiche client, and ngtcp2/nghttp3 client all pass `get-empty` and `split-data`, and quiche-server passes `get-empty` while its `split-data` row remains explicitly unwired.
- Latest focused external-server subset result: `incursa-client__quiche-server` passes `get-small`, `not-found`, and `get-large`; after routing and opening RFC 9287 greased fixed-bit long-header packets through the Incursa endpoint/runtime, `incursa-client__ngtcp2-server` passes `get-small`, `get-empty`, `not-found`, and `get-large` against the local `ngtcp2/nghttp3` `wsslserver` container.
- The 2026-06-19 plan-only normalized matrix run records 24 explicit rows for comma-separated PowerShell target/scenario arguments instead of collapsing them into a single skip row.
- The checked-in RFC 9114 and RFC 9204 floors are now traced in the repo; the remaining skip rows are interop/harness gaps, not a claim that the protocol floor is missing.
- `aioquic-client__incursa-server` is now executable for static GET-style rows and passes `get-small`, `get-empty`, `get-large`, `not-found`, `many-headers`, and `split-data`.
- `incursa-client__aioquic-server` is now executable for static GET-style rows and passes `get-small`, `get-empty`, `get-large`, `not-found`, `many-headers`, and `split-data`.
- `curl__incursa-server`, `quiche-client__incursa-server`, and `ngtcp2-client__incursa-server` are executable for the static client rows listed above with pinned local Docker images.
- `incursa-client__quiche-server` starts a fresh quiche server container per scenario and passes the static rows listed above.
- `incursa-client__ngtcp2-server` starts a fresh `wsslserver` container per scenario and now passes the executable static rows listed above; the remaining ngtcp2-server skip rows are unwired advanced HTTP/3 scenarios, not current failing peer evidence.

## Commands

Windows:

```powershell
pwsh -NoProfile -File scripts\interop\http3-external\Run-Http3ExternalInterop.ps1
```

Linux/macOS:

```bash
bash scripts/interop/http3-external/run-http3-external-interop.sh
```

## Debug Artifact Layout

Generated runs preserve the inputs needed for HTTP/3 interop triage:

```text
.artifacts/http3-external/<run-id>/
  results.jsonl
  report.md
  server.stdout.log
  server.stderr.log
  scenarios/<target>-<scenario>/
    command.txt
    stdout.log
    stderr.log
    http3-summary.json
  logs/<service>/
    qlog/
    sslkeylog/keys.log
  pcaps/
```

Use qvis for retained `.qlog` files and Wireshark with `sslkeylog/keys.log` for retained packet captures. Packet captures are copied into `pcaps/` when the harness is run with `-PcapSource` or `--pcap-source`.
