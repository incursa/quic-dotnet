# HTTP/3 Scope Note

This package covers the proven HTTP/3 floor used by `Incursa.Quic.Http3`.

## Proven Floors

- `SPEC-QUIC-RFC9114` now traces the HTTP/3 frame layer, stream mapping, SETTINGS exchange, header validation, malformed-sequence handling, and the minimal client/server request-response floor.
- `SPEC-QUIC-RFC9204` now traces the standalone QPACK integer codec, string literal codec, static table, field-section encoding and decoding, dynamic table accounting, blocked-stream synchronization, and encoder/decoder instruction parsing.
- Internal Incursa client/server GET flows are working.
- QLOG and TLS key-log artifact retention is in place for interop diagnosis.

## Interop Status

- `incursa-client__incursa-server` is green across the configured external scenarios.
- `aioquic-client__incursa-server` is green for the static GET-style rows that aioquic executes reliably.
- `incursa-client__aioquic-server` is green for the static GET-style rows that aioquic executes reliably.
- `curl__incursa-server` is skipped because the curl image is not built with HTTP/3 support.
- `quiche-client__incursa-server` and `ngtcp2-client__incursa-server` are skipped because the command shape and server wiring are not pinned to a deterministic scenario.
- Some advanced rows remain skipped where the peer wrapper does not expose a stable, deterministic behavior surface for the scenario.
- `aioquic-client__incursa-server` large-body rows are intentionally skipped because aioquic 1.3.0 drops the response delivery path on those cases.

## Scope Limits

- The package covers the HTTP/3 frame layer, stream mapping, SETTINGS exchange, header validation, malformed-sequence handling, and the minimal client/server request-response floor.
- The package does not include server push, trailers, CONNECT, HTTP Datagrams, MASQUE, or other out-of-scope features.
- The associated QPACK package covers the compression floor used by this package; the separate qlog repository owns the qlog model packages.

## Usage Note

- Use this package for the supported HTTP/3 floor and the current peer coverage described above.
- Treat the skipped rows as coverage gaps, not as package features.

## Good First Sample Applications

- Static site server: serve HTML, CSS, and JavaScript from a directory over HTTP/3, then verify it with curl and a browser.
- JSON API sample: expose a small in-memory API and consume it from a client over HTTP/3.
- Large file downloader: prove streaming DATA delivery, completion handling, and content-length correctness with a real download.
- Multi-request smoke app: issue several concurrent GETs to show multiplexing and request reuse.
- External API client: fetch a real HTTP/3-enabled public endpoint and display response metadata and body content.

## Evidence Pointer

See [docs/http3-external-interop-report.md](../../docs/http3-external-interop-report.md) for the checked-in interop summary and artifact layout.
