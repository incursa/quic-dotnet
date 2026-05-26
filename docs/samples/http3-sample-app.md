# Incursa HTTP/3 Sample App

The ObjectStore sample is a small console app that hosts the repository HTTP/3 layer directly on top of the Incursa QUIC transport. It is meant to prove a realistic application shape without introducing ASP.NET Core as the server.

The app lives at [`samples/Incursa.Http3.Samples.ObjectStore`](../../samples/Incursa.Http3.Samples.ObjectStore/). A smaller benchmark-shaped companion app lives at [`samples/Incursa.Http3.Samples.TechEmpower`](../../samples/Incursa.Http3.Samples.TechEmpower/).

## What It Proves

- HTTP/3 GET routing for HTML, CSS, JavaScript, image, text, and JSON responses.
- Multiple browser asset requests over separate HTTP/3 streams.
- Request header visibility through `/api/headers`.
- Request DATA body handling through `POST /api/files`.
- In-memory upload storage with SHA-256 reporting and download by id.
- A simple streaming response at `/api/stream`.
- Sample-level connection and request counters through HTTP/3 diagnostics.

This is not a broad HTTP/3 production-hosting claim. Server push, trailers, CONNECT, HTTP Datagrams, MASQUE, database access, and dynamic QPACK-heavy behavior remain outside this sample. The point is to keep a realistic app-shaped target in the repo so browser behavior, request bodies, response completion, and stream concurrency can be exercised against the custom Incursa QUIC + HTTP/3 stack.

## Run

From the repository root:

```powershell
dotnet run --project samples/Incursa.Http3.Samples.ObjectStore -- --port 4433
```

The app creates a short-lived localhost certificate if `--cert` and `--key` are not supplied. To use explicit PEM files:

```powershell
dotnet run --project samples/Incursa.Http3.Samples.ObjectStore -- --port 4433 --cert .\cert.pem --key .\priv.key
```

The default upload limit is 25 MB. Override it with:

```powershell
dotnet run --project samples/Incursa.Http3.Samples.ObjectStore -- --max-upload-bytes 1048576
```

On startup, the app prints browser launch commands for common Edge, Chrome, and Firefox install paths. Keep those commands visible; normal browser navigation to `https://localhost:4433/` can fail because the sample listens on HTTP/3 over QUIC/UDP only. Chromium-family browsers often try HTTPS over TCP unless HTTP/3 is forced for this local origin.

## Browser Testing

Use Edge or Chrome with a fresh profile and QUIC forced for the sample origin. The app startup output includes the current certificate SPKI hash, so prefer copying the printed command from your own run. A typical Edge command looks like this:

```powershell
& 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' --new-window --enable-quic --origin-to-force-quic-on=localhost:4433 --ignore-certificate-errors-spki-list=<printed-spki> --no-proxy-server --user-data-dir=.artifacts\http3-browser-debug\edge-profile https://localhost:4433/
```

A typical Chrome command is the same shape:

```powershell
& 'C:\Program Files\Google\Chrome\Application\chrome.exe' --new-window --enable-quic --origin-to-force-quic-on=localhost:4433 --ignore-certificate-errors-spki-list=<printed-spki> --no-proxy-server --user-data-dir=.artifacts\http3-browser-debug\chrome-profile https://localhost:4433/
```

Firefox is listed for completeness, but it does not provide a Chromium-style `--origin-to-force-quic-on` command-line switch. Use a configured Firefox profile that enables HTTP/3 for localhost and trusts the sample certificate before expecting Firefox to connect directly to this QUIC-only sample.

In browser DevTools, the document and asset requests should report `h3` as the protocol. The page should show the Incursa logo, the status payload, load the text asset, and update the JavaScript panel to `assets loaded over Incursa HTTP/3`.

## Test With curl

Use a curl build with HTTP/3 support:

```powershell
curl --http3-only --insecure https://localhost:4433/
curl --http3-only --insecure https://localhost:4433/api/status
curl --http3-only --insecure https://localhost:4433/api/headers?show=true -H "x-demo: incursa"
curl --http3-only --insecure https://localhost:4433/assets/app.css
```

Upload and download an in-memory file:

```powershell
'hello over h3' | curl --http3-only --insecure -X POST https://localhost:4433/api/files -H "content-type: text/plain" --data-binary '@-'
curl --http3-only --insecure https://localhost:4433/api/files/{id-from-upload}
```

## Test Streaming

The stream endpoint emits one text/event-style line about every 250 ms for 20 iterations:

```powershell
curl --http3-only --insecure --no-buffer https://localhost:4433/api/stream
```

Client cancellation is expected to be handled as a normal disconnect.

## Routes

- `GET /` returns the browser demo page.
- `GET /assets/app.css`, `/assets/app.js`, `/assets/sample.txt`, `/assets/incursa.svg`, and the additional Incursa logo/icon SVG variants return static assets with content types and content lengths where applicable.
- `GET /api/status` returns server, protocol, UTC timestamp, process id, active connection count, and active request count.
- `GET /api/headers` returns request method, path, query string, and request headers.
- `POST /api/files` stores an in-memory upload and returns id, byte count, SHA-256 hash, and content type.
- `GET /api/files/{id}` returns a stored upload or `404`.
- `GET /api/stream` emits one line every 250 ms for 20 iterations.
- `GET /api/errors/{code}` returns one of the supported sample error statuses.
- `GET /plaintext` and `GET /json` are convenience endpoints shared with the TechEmpower-shaped sample smoke path.

## Known Limitations

- Uploaded files are stored in memory only and disappear when the process exits.
- The generated development certificate is self-signed, so HTTP/3 clients need an insecure or test trust mode.
- The sample is QUIC/UDP-only. It does not also open an HTTPS/TCP fallback listener.
- The sample keeps routing deliberately small and does not provide middleware, filters, templating, or static-file directory serving.
- The smoke script includes `/plaintext` and `/json` convenience endpoints on ObjectStore so one process can cover both application and benchmark smoke paths.
