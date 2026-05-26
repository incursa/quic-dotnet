# Incursa Samples

This folder contains runnable sample applications that exercise the Incursa QUIC and HTTP/3 stack directly. They are intentionally small and do not use ASP.NET Core as the server.

## HTTP/3 ObjectStore

[`Incursa.Http3.Samples.ObjectStore`](Incursa.Http3.Samples.ObjectStore/) is the browser-facing HTTP/3 demo app. It serves an HTML page, static assets, JSON APIs, in-memory uploads, downloads, and a streaming endpoint over the repository QUIC transport.

Run it from the repository root:

```powershell
dotnet run --project samples/Incursa.Http3.Samples.ObjectStore -- --port 4433
```

The app prints Edge, Chrome, and Firefox launch notes at startup. Use the printed Chromium-family command when testing in a browser because the sample listens on HTTP/3 over QUIC/UDP only; a normal HTTPS tab can try TCP first and fail.

Detailed guide: [HTTP/3 sample app](../docs/samples/http3-sample-app.md).

## HTTP/3 TechEmpower Shape

[`Incursa.Http3.Samples.TechEmpower`](Incursa.Http3.Samples.TechEmpower/) exposes simple benchmark-shaped endpoints:

- `GET /plaintext`
- `GET /json`

The database-oriented TechEmpower routes are placeholders in this pass and return `501 Not Implemented`.

Benchmark notes: [HTTP/3 benchmarking](../docs/samples/http3-benchmarking.md).
