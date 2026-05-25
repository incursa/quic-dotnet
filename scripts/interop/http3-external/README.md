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

The first slice executes the Incursa and curl client paths against the Incursa server for static GET/404 scenarios. Other targets are represented in the result matrix and reported as `skip` until their exact command/server wiring is pinned.

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

The specialized behavior scenarios are intentionally reported as `skip` until a peer exposes deterministic endpoints for those behaviors.

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
- one log file per executed scenario.

Default output root:

```text
.artifacts/http3-external/<UTC-run-id>/
```

## Parser

```bash
python scripts/interop/http3-external/parse-http3-results.py \
  .artifacts/http3-external/<run-id>/results.jsonl \
  --output .artifacts/http3-external/<run-id>/report.md
```

## Requirements

- Docker with the compose plugin.
- Python 3 for the parser.
- OpenSSL for certificate generation when executing, unless `cert.pem` and `priv.key` are pre-created in the run `certs` directory.

## Boundary

This harness is not the upstream QUIC interop runner. It is an external HTTP/3 characterization harness and must not be used to claim broad RFC 9114/RFC 9204 completeness by itself.
