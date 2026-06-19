---
title: "HTTP/3 Benchmarking"
---

# HTTP/3 Benchmarking

The HTTP/3 benchmark scripts provide a first repeatable shape for comparing Incursa HTTP/3 against baseline implementations. They are TechEmpower-shaped, but this is not an official TechEmpower submission.

## Sample Server

Run the TechEmpower-shaped sample:

```powershell
dotnet run --project samples/Incursa.Http3.Samples.TechEmpower -- --port 4433
```

Implemented endpoints:

- `GET /plaintext` returns `Hello, World!` as `text/plain`.
- `GET /json` returns `{"message":"Hello, World!"}` as `application/json`.

Placeholder routes return `501 Not Implemented` until database behavior is intentionally added: `/db`, `/queries`, `/fortunes`, `/updates`, and `/cached-queries`.

## Recommended Baselines

- Incursa HTTP/3.
- ASP.NET Core Kestrel HTTP/3.
- Caddy HTTP/3.
- nginx HTTP/3.
- quic-go HTTP/3 sample server.

Keep TLS settings, host hardware, request counts, concurrency, response payloads, and client tool versions explicit when comparing results.

## First-Pass Metrics

- requests/sec
- latency percentiles
- errors
- CPU
- allocations/GC if available
- connection failures
- stream resets
- packet loss/retransmission counters if available

The included scripts preserve raw benchmark output under `.artifacts/http3-benchmarks/` because parser support is intentionally best-effort.

## Smoke

```powershell
pwsh -NoProfile -File scripts/benchmarks/Invoke-H3Smoke.ps1 -BaseUrl https://localhost:4433 -Insecure
```

The smoke script uses `curl --http3-only` and prints status, protocol, content type, and the first 200 response bytes for `/`, `/api/status`, `/api/headers`, `/plaintext`, and `/json`.

## h2load

Run one load case:

```powershell
pwsh -NoProfile -File scripts/benchmarks/Invoke-H3Load.ps1 -Tool h2load -BaseUrl https://localhost:4433 -Path /plaintext -Requests 100000 -Connections 256 -Streams 100 -Insecure
```

Run the comparison matrix:

```powershell
pwsh -NoProfile -File scripts/benchmarks/Invoke-H3Compare.ps1 -Tool h2load -BaseUrl https://localhost:4433 -Requests 100000 -Streams 100 -Insecure
```

## oha

Run one load case:

```powershell
pwsh -NoProfile -File scripts/benchmarks/Invoke-H3Load.ps1 -Tool oha -BaseUrl https://localhost:4433 -Path /json -Requests 100000 -Connections 256 -Insecure
```

Run the comparison matrix:

```powershell
pwsh -NoProfile -File scripts/benchmarks/Invoke-H3Compare.ps1 -Tool oha -BaseUrl https://localhost:4433 -Requests 100000 -Insecure
```

If a local `oha` build uses different HTTP/3 option names, run the printed command manually with the equivalent HTTP/3 and TLS verification flags and keep the raw output with the benchmark artifact.
