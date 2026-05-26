# External HTTP/3 Interop Harness

This harness is an advisory HTTP/3 peer matrix outside the upstream QUIC interop runner. It is intended to answer "which external HTTP/3 peers/scenarios currently work?" without promoting support from partial evidence.

## Targets

- `incursa-client__incursa-server`
- `curl__incursa-server`
- `aioquic-client__incursa-server`
- `quiche-client__incursa-server`
- `ngtcp2-client__incursa-server`
- `incursa-client__aioquic-server`
- `incursa-client__quiche-server`
- `incursa-client__ngtcp2-server`

The Incursa-to-Incursa lane executes all ten configured scenarios. The aioquic client lane executes the static GET-style scenarios against the Incursa server. Other targets are represented in the result matrix and reported as `skip` until their exact command/server wiring is pinned.

The default curl image is `curlimages/curl:latest`. If that image does not include HTTP/3 support, curl rows are reported as `skip`; set `HTTP3_CURL_IMAGE` to a curl build that supports `--http3-only` to execute them.

## Scenarios

- `get-small`
- `get-empty`
- `get-large`
- `multiple-concurrent-get`
- `not-found`
- `many-headers`
- `split-data`
- `request-cancellation`
- `goaway`
- `connection-close-in-flight`

The Incursa-to-Incursa lane includes deterministic endpoints for the specialized behavior scenarios. External peer lanes report these rows as `skip` until the peer wrapper exposes a deterministic command or route for the behavior.

The default `get-large` fixture is currently a bounded 64 KiB transfer. Multi-megabyte transfer characterization remains a transport/recovery follow-up and should not be inferred from this row.

Current coverage notes:

- `multiple-concurrent-get` uses multiple concurrent Incursa client containers/connections, not multiple request streams on one HTTP/3 connection.
- `connection-close-in-flight` is currently a bounded close-after-split-response fixture. It is useful for artifact retention and close-path smoke coverage, but it is not a proof of arbitrary abrupt mid-body peer failure handling.
- `curl__incursa-server` requires an HTTP/3-capable curl image. The default `curlimages/curl:latest` image is commonly skipped because it lacks `--http3-only`.

## Windows

```powershell
pwsh -NoProfile -File scripts\interop\http3-external\Run-Http3ExternalInterop.ps1 -PlanOnly
pwsh -NoProfile -File scripts\interop\http3-external\Run-Http3ExternalInterop.ps1
```

## Linux/macOS

```bash
bash scripts/interop/http3-external/run-http3-external-interop.sh --plan-only
bash scripts/interop/http3-external/run-http3-external-interop.sh
```

## Output

Each run writes:

- `results.jsonl`: machine-readable per-target/per-scenario rows.
- `report.md`: Markdown pass/fail/skip matrix.
- `scenarios/<target>-<scenario>/command.txt`: exact command line.
- `scenarios/<target>-<scenario>/stdout.log`: scenario stdout.
- `scenarios/<target>-<scenario>/stderr.log`: scenario stderr.
- `scenarios/<target>-<scenario>/http3-summary.json`: decoded scenario summary and debug artifact pointers.
- `logs/<service>/qlog/*.qlog`: qlog files when the peer honors `QLOGDIR`.
- `logs/<service>/sslkeylog/keys.log`: TLS secrets when the peer honors `SSLKEYLOGFILE`.
- `pcaps/`: copied packet captures when `-PcapSource` or `--pcap-source` is supplied.
- `server.stdout.log` and `server.stderr.log`: Incursa server container logs captured before shutdown.

Default output root:

```text
.artifacts/http3-external/<UTC-run-id>/
```

The compose file sets `QLOGDIR=/logs/qlog` and `SSLKEYLOGFILE=/logs/sslkeylog/keys.log` for every peer container. Implementations that do not support either variable simply leave the corresponding directory empty.

Packet capture is intentionally supplied by the caller so the harness can run without privileged containers by default:

```powershell
pwsh -NoProfile -File scripts\interop\http3-external\Run-Http3ExternalInterop.ps1 `
  -PcapSource C:\tmp\http3-pcaps
```

```bash
bash scripts/interop/http3-external/run-http3-external-interop.sh \
  --pcap-source /tmp/http3-pcaps
```

## Wireshark and qvis

- Open retained `pcaps/*.pcapng` or `pcaps/*.pcap` in Wireshark.
- Configure `Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename` to the retained `logs/<service>/sslkeylog/keys.log` file when present.
- Use the QUIC packet number space and HTTP/3 dissectors to correlate packet loss, stream resets, frame order, and content-length failures.
- Open retained `.qlog` files in qvis at https://qvis.quictools.info/ or with a local qvis instance.
- Prefer the Incursa qlog when diagnosing our endpoint state and the peer qlog when diagnosing disagreement about stream IDs, SETTINGS, QPACK instructions, or GOAWAY.

## Failed-Case Triage Checklist

- Confirm the scenario row in `results.jsonl` and `report.md` is `fail` rather than an explicit `skip`.
- Read `scenarios/<target>-<scenario>/command.txt`, `stdout.log`, and `stderr.log` before inspecting packet traces.
- Check `scenarios/<target>-<scenario>/http3-summary.json` for the expected URL, status, qlog directory, SSL key log, and pcap directory.
- Compare Incursa HTTP/3 qlog events for `settings_sent`, `settings_received`, `stream_opened`, `frame_sent`, `frame_received`, `request_started`, `response_completed`, `error`, and `connection_closed`.
- If Wireshark cannot decrypt the pcap, verify `SSLKEYLOGFILE` was populated and that the capture covers the same connection.
- If the peer closes first, map the frame or QPACK instruction immediately before close to RFC 9114/RFC 9204 before changing transport code.
- If only one peer fails, keep the row as peer-specific evidence and avoid promoting broad HTTP/3 support claims from other passing rows.

## Parser

```bash
python scripts/interop/http3-external/parse-http3-results.py \
  .artifacts/http3-external/<run-id>/results.jsonl \
  --output .artifacts/http3-external/<run-id>/report.md
```

## Requirements

- Docker with the compose plugin.
- Python 3 for fixture generation and the parser. The POSIX script honors `PYTHON_BIN` when `python3` or `python` is not on `PATH`.
- OpenSSL for ECDSA P-256 certificate generation when executing, unless compatible `cert.pem` and `priv.key` files are pre-created in the run `certs` directory.

## Boundary

This harness is not the upstream QUIC interop runner. It is an external HTTP/3 characterization harness and must not be used to claim broad RFC 9114/RFC 9204 completeness by itself.
