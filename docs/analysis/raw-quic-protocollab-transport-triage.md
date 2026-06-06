# Raw QUIC ProtocolLab transport triage

Date: 2026-06-06

Scope: ProtocolLab `quic-transport-v1-comparison` evidence for the Incursa raw QUIC adapter, focused on:

- `quic.transport.duplex-streams`
- `quic.transport.multiplex.100x64kb`
- `quic.transport.stream-throughput.1mb`

This note records the original failure and the 2026-06-06 focused fix. ProtocolLab benchmark classification semantics were not changed.

## Executive summary

ProtocolLab reported a real Incursa raw QUIC transport problem, not a site rendering problem.

The live report `local-all-20260604183008-quic-transport-v1-comparison` shows:

| Scenario | Incursa median | MSQuic/.NET median | Primary symptom |
| --- | ---: | ---: | --- |
| QUIC Duplex Streams | 2.67 req/s, 7,470.8 ms p95 | 588.73 req/s, 32.57 ms p95 | Incursa receives 0 echo bytes and times out on most/all operations. |
| QUIC Multiplex 100x64KB | 11.13 req/s, 11,093.82 ms p95 | 598.15 req/s, 143.76 ms p95 | Incursa receives 0 echo bytes and times out on every operation in the published reps. |
| QUIC Stream Throughput 1MB | 9.57 req/s, 161.01 ms p95 | 42.53 req/s, 18.19 ms p95 | Client-to-server upload completes, but at roughly one quarter of the MSQuic/.NET raw adapter throughput. |

The two echo scenarios are worse than "slow": the raw load tool sends data but records `bytesReceived=0` for Incursa. The report still says the cells passed because ProtocolLab validation proves endpoint setup and the load tool exits, while comparability captures the bad benchmark quality separately.

## 2026-06-06 fix and verification

Two focused changes moved the raw Duplex and Multiplex echo paths from timeout-class failures to delivered echo bytes:

- The Incursa raw ProtocolLab server now streams echo bytes while reading each bidirectional stream instead of buffering the full request body and echoing only after EOF.
- ProtocolLab local-source runs now force the raw server through `dotnet run -p:IncursaQuicSourceRoot=...` when `-IncursaQuicSourceRoot` is provided, so validation runs cannot accidentally execute a stale package-backed `IncursaRawQuicServer.dll`.

Focused repo-local loopback coverage was added for one connection with 16 and 100 concurrent bidirectional streams, each sending a 64 KiB payload and requiring the client to receive the full echo before EOF.

Verification:

| Check | Result |
| --- | --- |
| `dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S2P4_0006" -v minimal` | Passed: 6/6 |
| ProtocolLab Duplex `local-raw-quic-accept-duplex-20260606-quic-transport-v1-comparison`, `c1-s16-r1`, 30s duration, 10s warmup | `requestsPerSecond=179.68`, `latencyP95Ms=119.80`, `timeoutRequests=0`, `bytesSent=353370112`, `bytesReceived=353370112`, `comparabilityStatus=comparable-with-warnings`, validation `passed` |
| ProtocolLab Multiplex `local-raw-quic-accept-multiplex-20260606-quic-transport-v1-comparison`, `c1-s100-r1`, 30s duration, 10s warmup | `requestsPerSecond=178.40`, `latencyP95Ms=587.18`, `timeoutRequests=0`, `bytesSent=353894400`, `bytesReceived=353894400`, `comparabilityStatus=comparable-with-warnings`, validation `passed` |

The `comparable-with-warnings` status is expected for these local single-machine, adapter-backed runs. The important acceptance signal is that echo bytes are now received and the timeout-class failure is gone.

## Evidence reviewed

Live public report:

- <https://lab.incursa.com/reports/local-all-20260604183008-quic-transport-v1-comparison>
- Duplex Incursa cell: <https://lab.incursa.com/reports/local-all-20260604183008-quic-transport-v1-comparison/cells/incursa-raw-quic-adapter-v1-quic.transport.duplex-streams-quic-c1-s16-r1>
- Multiplex Incursa cell: <https://lab.incursa.com/reports/local-all-20260604183008-quic-transport-v1-comparison/cells/incursa-raw-quic-adapter-v1-quic.transport.multiplex.100x64kb-quic-c1-s100-r1>
- Stream throughput Incursa cell: <https://lab.incursa.com/reports/local-all-20260604183008-quic-transport-v1-comparison/cells/incursa-raw-quic-adapter-v1-quic.transport.stream-throughput.1mb-quic-c1-s1-r1>

Local sibling artifacts reviewed:

- `C:\shared\src\incursa\protocol-lab\.artifacts\runs\local-all-20260604183008-quic-transport-v1-comparison\...`
- Later local follow-up runs including `local-quic-fullfix4-quic-transport-v1-comparison` showed the same broad shape: Duplex remained around 2.5-2.9 req/s with 80-96 timeouts per rep, Multiplex remained around 10-12 req/s with timeouts, and Stream Throughput remained around 9-10 req/s.

Key local extraction from the published run:

| Implementation | Scenario | Reps | Median req/s | Median p95 | Timeouts | Failed | Bytes sent | Bytes received | Comparability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Incursa | Duplex | 3 | 2.67 | 7,470.8 ms | 272 | 0 | 17,825,792 | 0 | invalid |
| Incursa | Multiplex | 3 | 11.13 | 11,093.82 ms | 1,200 | 0 | 78,643,200 | 0 | invalid |
| Incursa | Stream Throughput | 3 | 9.57 | 161.01 ms | 1 | 1 | 896,842,614 | 0 | comparable-with-warnings |
| MSQuic/.NET | Duplex | 3 | 588.73 | 32.57 ms | 0 | 246 | 2,590,635,726 | 2,222,981,120 | mixed |
| MSQuic/.NET | Multiplex | 3 | 598.15 | 143.76 ms | 0 | 59 | 3,042,733,912 | 2,916,352,000 | comparable-with-warnings |
| MSQuic/.NET | Stream Throughput | 3 | 42.53 | 18.19 ms | 0 | 1 | 3,948,085,248 | 0 | comparable-with-warnings |

## What ProtocolLab is actually doing

The raw QUIC load generator has two relevant modes.

For Duplex and Multiplex, it opens bidirectional streams, writes the payload, closes the client write side, and then reads back exactly the same payload length. If the read side gets no bytes before the operation deadline, the request can still be recorded as "successful" when bytes were sent, but it is also counted as a timeout and records zero received bytes. That is why the report can show `passed` and `succeeded` while the benchmark is unusable.

For Stream Throughput, the scenario is `client-to-server`. The load tool does not expect a response, so `bytesReceived=0` is normal there. The problem in that row is pure upload throughput and latency, not echo failure.

## Why Duplex and Multiplex are unusable

Confirmed facts:

- The Incursa raw server stores the whole inbound request body into a `MemoryStream` before writing any echo response.
- The server then copies the buffered body back to the same QUIC stream and calls `CompleteWritesAsync`.
- The load tool expects the response bytes after closing the client write side.
- Published Incursa Duplex and Multiplex artifacts record `bytesSent > 0`, `bytesReceived = 0`, and timeout warnings.

This means the Incursa raw benchmark server is not exercising a true duplex streaming echo. It is request-buffer-then-response. That design is survivable for one small stream, but it is hostile to these two shapes:

- Duplex: 16 concurrent bidirectional streams, each 64 KiB, response expected on every stream.
- Multiplex: 100 concurrent bidirectional streams, each 64 KiB, response expected on every stream.

The pressure point is made worse by Incursa's default receive windows:

- Default per-stream receive window is 64 KiB.
- The benchmark payload for Duplex and Multiplex is exactly 64 KiB.
- The server's default inbound bidirectional stream limit is 100, so Multiplex can open all streams, but all 100 streams can consume their entire initial per-stream receive credit immediately.

That combination creates a "read full stream, issue credit, then echo full stream" pattern across many streams. Published artifacts show the response side does not make observable progress before the load generator deadline: every Incursa Multiplex operation in the published reps times out with zero received bytes.

## Why Stream Throughput is poor

Stream Throughput is not the same failure mode. It is a client-to-server upload and does not require echo bytes. Incursa completes many uploads, but at about 9-10 req/s for 1 MiB payloads, versus about 42.5 req/s for the MSQuic/.NET adapter in the same report.

The strongest static suspects are:

- Incursa's public stream write path splits non-final writes larger than 16 KiB into sequential `WriteStreamAsyncCore` calls. A 1 MiB upload is at least 64 runtime write actions before packet-level fragmentation and retransmission behavior.
- The receive side reads in 64 KiB chunks and posts flow-control credit updates through the connection runtime. For a 1 MiB upload, that is repeated receive-buffer work and repeated credit update publication.
- Application stream writes and flow-control updates are serialized through the connection runtime's event path and send queue. Under single-stream upload this shows up as lower throughput; under 16 or 100 concurrent echo streams it turns into timeouts.

This is an inference from code plus artifacts, not a profiler-confirmed attribution. The current published raw QUIC artifacts do not include target counters, qlog, packet capture, or per-runtime queue diagnostics for the Incursa raw server process.

## Not the primary cause

These are visible in the report but are not the core explanation for the three bad Incursa rows:

- Shared-host local run warnings: they make the evidence non-publishable, but they do not explain Incursa being two orders of magnitude behind MSQuic/.NET in the same local comparison.
- TLS resumption unsupported smoke warning: present across raw QUIC cells; it is not specific to Duplex, Multiplex, or Stream Throughput.
- Stream-count limit: the server default inbound bidirectional stream limit is 100, matching the Multiplex scenario. Multiplex is not failing because the stream limit is below the requested count.
- The public site: the raw `result.json` artifacts carry the same `bytesReceived=0`, timeout, RPS, and comparability signals shown by the site.

## Completed proof steps

1. Added and used narrow Incursa raw server debug logging for per-stream read, echo, EOF, and completion milestones.

2. Confirmed the first local reruns were misleading because the raw server launcher was executing stale package-backed output. The source-root launcher path now records `dotnet run --configuration Release --no-launch-profile --project ... -p:IncursaQuicSourceRoot=...` in each server command artifact.

3. Built a repo-local loopback test for concurrent raw bidirectional echo with ProtocolLab-sized payloads:
   - 1 connection, 16 streams, 64 KiB each.
   - 1 connection, 100 streams, 64 KiB each.
   - Assert every client receives the echoed payload, not just that streams open.

4. Measured the server echo hypothesis separately. Streaming echo while reading fixes the Duplex and Multiplex timeout-class failure once the raw server is proven to run against local Incursa QUIC bits.

5. Reran ProtocolLab `quic-transport-v1-comparison` for the two focused cells and inspected `timeoutRequests`, `bytesReceived`, comparability status, RPS, and p95.

## Current working conclusion

Duplex and Multiplex were unusable because the ProtocolLab Incursa raw server buffered each request body before echoing and local source-reference runs could silently execute stale package-backed server output. With streaming echo and source-root server launch, ProtocolLab-sized Duplex and Multiplex runs now deliver echo bytes reliably with zero timeouts in the focused local acceptance artifacts.

Stream Throughput remains a different hot-path problem: large client-to-server stream writes are making progress, but the current Incursa stream write/read/flow-control path is still much slower than the MSQuic/.NET adapter. That work was intentionally left out of this Duplex/Multiplex slice.

Treat any remaining Stream Throughput or HTTP/3/header/QPACK performance work as separate follow-up slices. This slice changed the raw echo path and local source-reference execution only.
