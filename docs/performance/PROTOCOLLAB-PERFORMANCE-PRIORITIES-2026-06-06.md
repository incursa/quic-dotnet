# ProtocolLab Performance Priorities - 2026-06-06

## Evidence Sources

- Live site inspected: https://lab.incursa.com/ on 2026-06-06.
- Latest public homepage report: `local-quic-dev-20260605231202-quic-transport-v1-comparison`, published 2026-06-06 05:12 UTC. This is a one-cell local raw-QUIC validation report for `quic.transport.multiplex.100x64kb`; it is rejected as benchmark evidence because of invalid comparability status.
- Public H3 comparison report: `local-quic-dev-20260605190927-h3-local-v1-comparison`, local-lab smoke profile, 30 accepted benchmark cells and 6 load-tool failures.
- Public raw transport comparison report: `local-all-20260604183008-quic-transport-v1-comparison`, local-lab comparison profile.
- Local focused timeout artifacts reviewed before this list showed `quic.transport.multiplex.100x64kb` completing validation but timing out with `bytesReceived=0` and a single 64 KB request payload sent, so timeout-class behavior is treated as higher priority than ordinary RPS gaps.

## Interpretation Rules

- Treat these as local-lab triage numbers, not publishable claims. The public reports warn about single-machine execution, missing resource isolation, and limited repetitions.
- Rank within comparable load profiles. Do not blend H3 smoke rows and raw transport comparison rows into one absolute benchmark claim.
- Prefer fixing real quic-dotnet runtime behavior over changing ProtocolLab semantics. Harness changes are only in scope when evidence proves the harness is wrong.
- Commit runtime changes only after a before/after ProtocolLab run shows measured improvement for the targeted scenario without obvious adjacent regressions.

## Priority List

| Priority | Scenario | Evidence | Current Incursa result | Comparator / status | Why this is first-class |
| --- | --- | --- | --- | --- | --- |
| P0 | `quic.transport.duplex-streams` | `local-all-20260604183008-quic-transport-v1-comparison` | 2.674 RPS, p95 7470.80 ms, 0.5% of best | MSQuic/.NET 588.726 RPS | Worst accepted raw transport gap. Points at stream scheduling, send queue flushing, retransmission/ACK progress, or stream lifecycle behavior. |
| P0 | `quic.transport.multiplex.100x64kb` | latest public report plus focused local timeout artifacts | latest focused runs time out with `bytesReceived=0`; older comparison: 11.130 RPS, p95 11093.82 ms, 1.9% of best | MSQuic/.NET 598.151 RPS; latest public benchmark rejected | Timeout-class failure in the focused source-reference loop. This blocks trustworthy transport performance comparisons. |
| P1 | `http.upload.sink.1mb`, `http.upload.hash.1mb`, `http.upload.echo.64kb` | `local-quic-dev-20260605190927-h3-local-v1-comparison` | Incursa rows not run: load tool exited with code 1 | Kestrel and quic-go accepted | These are correctness/liveness blockers above transport. They should map to `http3-large-body-completion` before optimization work. |
| P1 | `http.headers.response.50x32` | `local-quic-dev-20260605190927-h3-local-v1-comparison` | 1500.458 RPS, p95 6.41 ms, 17.5% of best | Kestrel 8577.388 RPS | Largest accepted H3 RPS gap. Likely pressure is QPACK/header block encode, response header enumeration, and HTTP/3 frame emission. |
| P2 | `quic.transport.stream-throughput.1mb` | `local-all-20260604183008-quic-transport-v1-comparison` | 9.566 RPS, p95 161.01 ms, 22.5% of best | MSQuic/.NET 42.526 RPS | Single-stream bulk transfer isolates payload send/receive buffering better than multiplex. Work here may also help H3 payload rows. |
| P2 | `http.payload.bytes.64kb` and `http.payload.bytes.1mb` | `local-quic-dev-20260605190927-h3-local-v1-comparison` | 64 KB: 179.423 RPS, 24.7% of best; 1 MB: 16.107 RPS, 23.8% of best | Kestrel is best for both | Payload-heavy H3 accepted rows are slow even when they do not fail. Likely affected by transport stream write/read buffering and H3 DATA frame chunking. |
| P3 | H3 small response rows: `http.core.*`, `http.payload.bytes.1kb`, `http.headers.inspect-request` | `local-quic-dev-20260605190927-h3-local-v1-comparison` | About 39.8%-41.4% of best | Kestrel/quic-go | Meaningful but less urgent than timeout/not-run and large accepted gaps. Useful once larger stream/header bottlenecks are reduced. |
| P3 | `quic.transport.connection-churn` | `local-all-20260604183008-quic-transport-v1-comparison` | 79.612 RPS, p95 14.07 ms, 37.8% of best | MSQuic/.NET 210.637 RPS | Still behind, but prior allocation work already reduced major churn costs. Lower priority than active stream liveness and bulk-transfer bottlenecks. |

## First Implementation Slice

Start with the raw transport stream-send path because it owns the two worst public raw QUIC scenarios and the current focused timeout loop:

- Requirement/gap anchor: `queued-stream-send-ownership` in `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Source areas: `QuicApplicationSendQueue`, `TryPromoteQueuedApplicationSendToFinal`, `FlushPendingApplicationSends`, `QuicConnectionSendRuntime`, and stream write paths under `src/Incursa.Quic`.
- Proof path: focused unit/behavior tests for queued stream-send ownership/progress, then the ProtocolLab source-reference loop for `quic.transport.multiplex.100x64kb`.
- Stop rule: if focused raw multiplex remains timeout-class after bounded runtime changes, move to `http.headers.response.50x32` or single-stream `quic.transport.stream-throughput.1mb` rather than broadening the patch.

## 2026-06-06 Execution Note

- Focused raw multiplex baseline artifact `codex-clean-baseline-20260606-quic-transport-v1-comparison` stayed timeout-class: `timeoutRequests=1`, `bytesReceived=0`, comparability `invalid`.
- A bounded stream-write chunking experiment did not improve the focused raw multiplex artifact, so it was backed out rather than committed.
- Work moved to the next accepted H3 gap, `http.headers.response.50x32`, where QPACK static table scans were visible in response header encode/decode source review.
- The committed H3 slice should stay separate from the raw timeout work: raw final check `codex-final-raw-check-20260606-quic-transport-v1-comparison` still records `timeoutRequests=1`, `bytesReceived=0`, comparability `invalid`.
