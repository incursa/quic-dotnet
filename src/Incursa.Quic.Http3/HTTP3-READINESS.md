# HTTP/3 Readiness Note

This package is ready for product work on the proven HTTP/3 floor, but it is not honest to call the full interop matrix "all green" yet.

## Proven Floors

- `SPEC-QUIC-RFC9114` now traces the HTTP/3 frame layer, stream mapping, SETTINGS exchange, header validation, malformed-sequence handling, and the minimal client/server request-response floor.
- `SPEC-QUIC-RFC9204` now traces the standalone QPACK integer codec, string literal codec, static table, field-section encoding and decoding, dynamic table accounting, blocked-stream synchronization, and encoder/decoder instruction parsing.
- Internal Incursa client/server GET flows are working.
- QLOG and TLS key-log artifact retention is in place for interop diagnosis.

## Interop Status

- `incursa-client__incursa-server` is green across the configured external scenarios.
- `aioquic-client__incursa-server` is green for the static GET-style rows that aioquic executes reliably.
- `incursa-client__aioquic-server` is green for the static GET-style rows that aioquic executes reliably.
- `curl__incursa-server` remains skipped until the curl image is set to an HTTP/3-capable build.
- `quiche-client__incursa-server` and `ngtcp2-client__incursa-server` remain skipped until the exact command and server wiring are pinned and kept deterministic.
- Some advanced rows remain skipped where the peer wrapper does not expose a stable, deterministic behavior surface for the scenario.
- `aioquic-client__incursa-server` large-body rows are intentionally skipped because aioquic 1.3.0 drops the response delivery path on those cases.

## What Is Still Not Proven

- The full external peer matrix is not green.
- The RFC 9114 / RFC 9204 floor is proven, but the broader HTTP/3 and QPACK planning gaps that remain in [REQUIREMENT-GAPS.md](../../specs/requirements/quic/REQUIREMENT-GAPS.md) are intentionally deferred:
  - future HTTP/3 adapter features beyond the proven floor
  - future QPACK HTTP/3 integration-side state capture/restore work
  - server push, trailers, CONNECT, HTTP Datagrams, MASQUE, and other out-of-slice features

## What This Means

- Yes, it is reasonable to start building real HTTP/3-facing samples and product code on top of this floor.
- No, it is not reasonable to describe the entire RFC 9114 / RFC 9204 interop story as complete.
- Treat the remaining work as interop expansion, peer coverage, and future-RFC feature work, not as a blocker to beginning useful application work.

## Good First Sample Applications

- Static site server: serve HTML, CSS, and JavaScript from a directory over HTTP/3, then verify it with curl and a browser.
- JSON API sample: expose a small in-memory API and consume it from a client over HTTP/3.
- Large file downloader: prove streaming DATA delivery, completion handling, and content-length correctness with a real download.
- Multi-request smoke app: issue several concurrent GETs to show multiplexing and request reuse.
- External API client: fetch a real HTTP/3-enabled public endpoint and display response metadata and body content.

## Evidence Pointer

See [docs/http3-external-interop-report.md](../../docs/http3-external-interop-report.md) for the checked-in interop summary and artifact layout.
