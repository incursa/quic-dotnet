---
title: "QUIC Interop Runner HTTP/3"
---

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

## Debug Artifacts

The endpoint honors the standard interop environment variables used for protocol
debugging:

- `QLOGDIR`: when set, client and server HTTP/3 paths attach a qlog diagnostics
  sink and write qlog snapshots under the supplied directory.
- `SSLKEYLOGFILE`: when the active TLS provider supports secret export, TLS
  traffic secrets are written to this file for Wireshark decryption. If the
  provider cannot export secrets, the path remains absent rather than containing
  synthetic key material.

Expected artifact layout for an HTTP/3 runner attempt:

```text
<artifact-root>/
  runner-report.json
  runner-report.md
  runner-logs/
    <peer>_<role>/http3/
      client|server stdout/stderr
      qlog/
      sslkeylog/
      sim/
        trace_node_left.pcap
        trace_node_right.pcap
```

## Wireshark and qvis

- Open runner `sim/*.pcap` files in Wireshark.
- Point Wireshark TLS secrets to the retained `sslkeylog/keys.log` file when it
  exists.
- Use qvis to inspect retained `.qlog` files and correlate HTTP/3 events with
  QUIC packet loss, stream resets, and connection-close timing.
- Start with Incursa qlogs for local state-machine behavior and peer qlogs for
  stream/frame disagreement.

## HTTP/3 Failure Triage

- Confirm the interop runner classified the cell as `http3` and not a delegated
  non-HTTP/3 testcase.
- Inspect stdout/stderr for endpoint exit code `1` failures before packet traces.
- Check qlog event order: connection started, SETTINGS sent/received, QPACK
  stream instructions, request HEADERS, response HEADERS, DATA, stream close,
  connection close.
- If the failure involves malformed frames or QPACK, map the close/error to the
  RFC 9114 or RFC 9204 requirement before changing transport behavior.
- If the pcap does not decrypt, verify `SSLKEYLOGFILE` exists and belongs to the
  same run.
