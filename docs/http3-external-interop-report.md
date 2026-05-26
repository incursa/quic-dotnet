# External HTTP/3 Interop Report

This is the checked-in report template for the external HTTP/3 interop harness. Run the harness to generate a current report under `.artifacts/http3-external/<run-id>/report.md`.

Last refreshed from local Docker evidence on 2026-05-26.

- Default matrix run: `.artifacts/http3-final-default-after-huffman/20260526T040847Z`
- Focused Incursa advanced run: `.artifacts/http3-all-advanced-default/20260526T033718Z`
- Focused aioquic static GET-style run: `.artifacts/http3-aioquic-after-huffman2/20260526T040811Z`
- Incursa proof: `incursa-client__incursa-server` passes all ten configured scenarios.
- External-provider proof: `aioquic-client__incursa-server` passes the executable static GET-style scenarios after adding QPACK Huffman string-literal decoding.

## Current Checked-In Matrix

| Target | get-small | get-empty | get-large | multiple-concurrent-get | not-found | many-headers | split-data | request-cancellation | goaway | connection-close-in-flight |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| incursa-client__incursa-server | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| curl__incursa-server | skip | skip | skip | skip | skip | skip | skip | skip | skip | skip |
| aioquic-client__incursa-server | pass | pass | pass | skip | pass | pass | pass | skip | skip | skip |
| quiche-client__incursa-server | skip | skip | skip | skip | skip | skip | skip | skip | skip | skip |
| ngtcp2-client__incursa-server | skip | skip | skip | skip | skip | skip | skip | skip | skip | skip |
| incursa-client__aioquic-server | skip | skip | skip | skip | skip | skip | skip | skip | skip | skip |
| incursa-client__quiche-server | skip | skip | skip | skip | skip | skip | skip | skip | skip | skip |
| incursa-client__ngtcp2-server | skip | skip | skip | skip | skip | skip | skip | skip | skip | skip |

## Current Findings

- `incursa-client__incursa-server` passes `get-small`, `get-empty`, `get-large`, `multiple-concurrent-get`, `not-found`, `many-headers`, `split-data`, `request-cancellation`, `goaway`, and `connection-close-in-flight` in Docker with qlog capture and preserved stdout/stderr.
- Latest default matrix result: `16 pass`, `0 fail`, `64 skip`.
- `aioquic-client__incursa-server` is now executable for static GET-style rows and passes `get-small`, `get-empty`, `get-large`, `not-found`, `many-headers`, and `split-data`.
- `curl__incursa-server` rows are `skip` with the default `curlimages/curl:latest` image because that image does not support `--http3-only`. Set `HTTP3_CURL_IMAGE` to a curl build with HTTP/3 support to make these rows executable.
- `quiche`, `ngtcp2`, and Incursa-client-to-external-server rows remain `skip` until their command/server wiring is pinned.

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
