# HTTP/3 Readiness Note

This package is ready for product work on the proven HTTP/3 floor, but it is not honest to call the full interop matrix "all green" yet.

## Current Status

- `Incursa.Quic.Http3` is implemented and usable for the core request/response path.
- Internal Incursa client/server GET flows are working.
- External interop is partially green.
- `aioquic-client__incursa-server` large-body rows are intentionally skipped because aioquic 1.3.0 drops the response delivery path on those cases.

## What Is Proven

- Basic HTTP/3 request and response flow over the managed QUIC transport.
- Static GET-style interop between Incursa and curl when the curl image has HTTP/3 support.
- QLOG and TLS key-log artifact retention for interop diagnosis.
- The HTTP/3 floor needed for local samples, basic APIs, and static content delivery.

## What Is Still Not Proven

- The full external peer matrix is not green.
- Some provider-specific lanes are still skipped until the exact peer image and command wiring are pinned.
- Advanced scenarios such as cancellation, GOAWAY, and in-flight connection close still need broader peer coverage before they can be called fully proven across the matrix.

## What This Means

- Yes, it is reasonable to start building real HTTP/3-facing samples and product code on top of this floor.
- No, it is not reasonable to describe the entire RFC 9114 / RFC 9204 interop story as complete.
- Treat the remaining work as interop expansion and peer coverage, not as a blocker to beginning useful application work.

## Good First Sample Applications

- Static site server: serve HTML, CSS, and JavaScript from a directory over HTTP/3, then verify it with curl and a browser.
- JSON API sample: expose a small in-memory API and consume it from a client over HTTP/3.
- Large file downloader: prove streaming DATA delivery, completion handling, and content-length correctness with a real download.
- Multi-request smoke app: issue several concurrent GETs to show multiplexing and request reuse.
- External API client: fetch a real HTTP/3-enabled public endpoint and display response metadata and body content.

## Evidence Pointer

See [docs/http3-external-interop-report.md](../../docs/http3-external-interop-report.md) for the checked-in interop summary and artifact layout.
