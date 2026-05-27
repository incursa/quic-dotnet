# Incursa H3 Request-Response Path

This document maps the current Incursa HTTP/3 sample-server request path from UDP receive through QUIC, HTTP/3, QPACK, sample route dispatch, response framing, stream writes, packet protection, and UDP send. It is diagnostic only. It does not classify benchmark evidence, change benchmark status, or propose bypassing protocol behavior.

## Scope

Reviewed code paths:

- `samples/Incursa.Http3.Samples.TechEmpower/Program.cs`
- `src/Incursa.Quic.Http3/Http3Server.cs`
- `src/Incursa.Quic.Http3/Http3FrameReader.cs`
- `src/Incursa.Quic.Http3/Http3FrameWriter.cs`
- `src/Incursa.Quic.Http3/Http3StreamDispatcher.cs`
- `src/Incursa.Quic.Http3/Http3Request.cs`
- `src/Incursa.Quic.Http3/Http3ServerResponse.cs`
- `src/Incursa.Qpack/QPackDecoder.cs`
- `src/Incursa.Qpack/QPackEncoder.cs`
- `src/Incursa.Quic/QuicListenerHost.cs`
- `src/Incursa.Quic/QuicConnectionRuntimeEndpoint.cs`
- `src/Incursa.Quic/QuicConnectionRuntimeHost.cs`
- `src/Incursa.Quic/QuicConnectionRuntimeShard.cs`
- `src/Incursa.Quic/QuicConnectionRuntime.Protocol.cs`
- `src/Incursa.Quic/QuicConnectionRuntime.Streams.cs`
- `src/Incursa.Quic/QuicStream.cs`
- `src/Incursa.Quic/QuicApplicationSendQueue.cs`
- `src/Incursa.Quic/QuicConnectionSendRuntime.cs`
- `src/Incursa.Quic/QuicFrameCodec.cs`
- `src/Incursa.Quic/QuicPacketParser.cs`
- `src/Incursa.Quic/QuicHandshakeFlowCoordinator.cs`

## End-To-End Path

1. Listener startup
   - Main entry: `Program.Main` configures `Http3Server.ListenAsync` with ALPN `h3`, broad stream limits, and 16 MiB receive windows.
   - Main files/classes/methods: `Program.Main`, `Program.CreateListenerOptions`, `Http3Server.ListenAsync`, `QuicListener.ListenAsync`, `QuicListenerHost.RunAsync`.
   - Hot-path status: connection setup only for steady-state requests after connections are established.
   - Risks: certificate generation is startup-only. Listener accept uses a bounded `Channel<object>` and `Http3Server` tracks connection tasks under a `lock`; neither is expected per request after connection acceptance.

2. UDP receive
   - Main files/classes/methods: `QuicListenerHost.ReceiveLoopAsync`.
   - Flow: a pooled 4096 byte receive buffer is used with `Socket.ReceiveMessageFromAsync`; each datagram is copied into a new `byte[]` before routing.
   - Hot-path status: likely hot per UDP datagram.
   - Allocation/copy: `buffer.AsSpan(...).ToArray()` allocates and copies once per received datagram.
   - Await/queue: one socket await per datagram.
   - Batching opportunity: possible packet/receive batching is not visible here; the current receive loop handles one datagram at a time.

3. Connection lookup and endpoint ingress
   - Main files/classes/methods: `QuicConnectionRuntimeEndpoint.ReceiveDatagram`, `ReceiveShortHeaderDatagram`, `TryLookupRouteByPrefix`, `TryPostPacketReceived`, `QuicConnectionRuntimeHost.TryPostEvent`, `QuicConnectionRuntimeShard.TryPost`.
   - Flow: endpoint classifies the packet header, looks up route dictionaries, and posts a connection event into a shard channel.
   - Hot-path status: likely hot per datagram.
   - Allocation/copy: event object/record allocations are likely per datagram; route lookup itself is dictionary-based.
   - Locks/queues: heavy use of `ConcurrentDictionary`; each packet is routed through an unbounded shard `Channel`.
   - Batching opportunity: current shape is one datagram to one posted work item.

4. Packet parsing and packet protection open
   - Main files/classes/methods: `QuicPacketParser.TryClassifyHeaderForm`, `QuicPacketParser.TryParseShortHeader`, `QuicConnectionRuntime.Protocol.TryHandleApplicationPacketReceived`, `QuicHandshakeFlowCoordinator.TryOpenProtectedApplicationDataPacketLease`.
   - Flow: app-data packets are opened with current, retained-old, or successor packet protection material, then packet number, spin bit, ACK, and frame payload are processed.
   - Hot-path status: likely hot per protected packet.
   - Allocation/copy: the open path uses `QuicBufferLease`, which is a positive sign; frame parsing still creates arrays for some frame payloads.
   - Await/queue: runs inside the shard consumer, not directly on the socket thread after event posting.
   - Batching opportunity: currently packet payload parsing is per packet.

5. ACK and loss recovery interaction
   - Main files/classes/methods: `QuicConnectionRuntime.Protocol.HandleApplicationAckFrame`, `QuicConnectionSendRuntime.TryAcknowledgePacket`, `TryRegisterLoss`, `TryArmProbeTimeout`.
   - Flow: ACK frames update sent-packet and congestion/recovery state. Receive-side packet processing records ACK-eliciting status and can flush application sends after recovery progress.
   - Hot-path status: likely hot when peer ACKs are frequent.
   - Allocation/copy: sent-packet tracking uses dictionaries and record structs; suppression helpers scan retained packet payloads.
   - Queues: retransmission queue can hold packet bytes and stream IDs for retransmission.
   - Batching opportunity: ACK coalescing and delayed send behavior need measurement before any claim.

6. Stream frame dispatch and stream state
   - Main files/classes/methods: `QuicConnectionRuntime.Protocol.TryHandleApplicationPacketReceived`, `QuicStreamParser.TryParseStreamFrame`, `QuicConnectionStreamState.TryReceiveStreamData`, `QuicConnectionRuntime.NotifyStreamObservers`, `QuicStream.HandleRuntimeNotification`.
   - Flow: STREAM frames are parsed, committed to stream receive state, and stream observers are notified. `QuicStream.ReadAsync` waits on a `SemaphoreSlim` and drains bytes from the stream-state seam.
   - Hot-path status: likely hot per request-body/header bytes and response ACK progress.
   - Allocation/copy: stream payloads are represented as byte arrays in several seams; stream notifications fan out through `ConcurrentDictionary` observers.
   - Locks/queues: `QuicStream` has read and write semaphores.
   - Batching opportunity: app reads are decoupled from packet receive by runtime notifications and stream-state buffers.

7. HTTP/3 stream acceptance
   - Main files/classes/methods: `Http3Server.ServeAsync`, `HandleConnectionAsync`, `AcceptStreamsAsync`, `QuicConnection.AcceptInboundStreamAsync`, `QuicConnectionRuntime.AcceptInboundStreamAsync`.
   - Flow: each accepted bidirectional QUIC stream becomes a request stream. The server starts `HandleRequestStreamAsync` without retaining or awaiting the task.
   - Hot-path status: hot per request stream.
   - Allocation/copy: task allocation per accepted stream; new `Http3StreamDispatcher` per connection.
   - Locks/queues: `dispatcherGate` lock guards stream dispatcher updates.
   - Batching opportunity: request streams are handled concurrently, but dispatch and stream bookkeeping remain per stream.

8. HTTP/3 frame parsing
   - Main files/classes/methods: `Http3Server.ReadRequestAsync`, `Http3FrameReader.Read`, `ProcessRequestFrameAsync`.
   - Flow: each request stream allocates a read buffer and a `Http3FrameReader`. Incoming stream bytes are appended into `pending`; complete frames allocate payload arrays and frame objects.
   - Hot-path status: likely hot per request.
   - Allocation/copy: `Http3FrameReader.Append`, payload `ToArray()`, frame objects, and result arrays occur on the path.
   - Await/queue: `ReadRequestAsync` awaits stream reads until end of request stream.
   - Batching opportunity: parser could eventually parse over buffers without payload copies, but this needs measurement first.

9. QPACK/header decoding
   - Main files/classes/methods: `ConnectionQPackState.DecodeRequestHeadersAsync`, `QPackDecoder.DecodeFieldSection`, `QPackStringLiteral`, `Http3HeaderValidator.ValidateRequestHeaders`.
   - Flow: request HEADERS payload is decoded after peer SETTINGS are known. The minimal benchmark path appears to use static/literal QPACK; dynamic-table blocked streams are supported but probably not dominant for h2load tiny requests unless h2load uses dynamic QPACK.
   - Hot-path status: likely hot per request.
   - Allocation/copy: decoded headers are strings and `QPackFieldLine[]`; `QPackDecoder` copies encoded field sections in some paths.
   - Locks/queues: connection QPACK state has a `lock` and `TaskCompletionSource` for blocked sections.
   - Batching opportunity: static table lookup and decoded header object reuse might matter, but should be measured first.

10. Request object creation and sample route dispatch
    - Main files/classes/methods: `Http3Server.CreateRequest`, `Http3Request` constructor, `TechEmpowerHandler.HandleAsync`, `HandleGet`, `Payload`.
    - Flow: validated pseudo-headers become an `Http3Request`; sample handler strips query, compares path/method, and creates `Http3ServerResponse`.
    - Hot-path status: hot per request.
    - Allocation/copy: `Http3Request.Body = body.ToArray()` and `Http3ServerResponse.Body = body.ToArray()` copy even tiny empty/prebuilt bodies. The handler formats `date` and `content-length` strings per response.
    - Locks/queues: none obvious in route dispatch.
    - Batching opportunity: common-path response/header reuse is plausible, but correctness around `date` and response ownership must be preserved.

11. Response header encoding
    - Main files/classes/methods: `Http3Server.BuildResponseHeaders`, `EncodeResponseFieldSection`, `FindStaticFieldLineIndex`, `FindStaticNameIndex`, `WriteRawString`, `QPackStaticTable`.
    - Flow: response headers are rebuilt into an array, encoded with local static/literal QPACK helpers, then wrapped in a HEADERS frame.
    - Hot-path status: likely hot per request.
    - Allocation/copy: `BuildResponseHeaders` uses `ArrayBufferWriter<QPackFieldLine>` and returns `ToArray`; `EncodeResponseFieldSection` encodes strings to new byte arrays; static table lookups scan the table per header.
    - Locks/queues: none.
    - Batching opportunity: repeated response headers and static table lookup results are likely measurement candidates.

12. DATA frame generation and stream writes
    - Main files/classes/methods: `Http3FrameWriter.WriteHeaders`, `WriteData`, `WriteBufferedResponseFramesAsync`, `WriteFinalFrameBytesAsync`, `QuicStream.WriteAsync`, `WriteFinalAsync`.
    - Flow: for non-empty buffered responses, headers and DATA frames are combined into one array, then written as a final stream write. For empty responses, headers are final. Small responses are not intentionally split by H3 after buffering.
    - Hot-path status: likely hot per response.
    - Allocation/copy: `Http3FrameWriter.WriteFrame` returns new arrays; `WriteBufferedResponseFramesAsync` calls `WriteData` for each data frame and writes those arrays into another writer, then `ToArray()` again.
    - Await/queue: each stream write awaits through `QuicStream` and runtime API posting; final write completes stream send side.
    - Batching opportunity: response H3 frames are mostly batched before QUIC stream write for tiny responses, but the lower QUIC send path may still produce one UDP send per stream write or per packet.

13. QUIC stream write and packet building
    - Main files/classes/methods: `QuicStream.WriteCoreAsync`, `WriteFinalCoreAsync`, `QuicConnectionRuntime.WriteStreamAsync`, `HandleWriteStreamAction`, `TryBuildOutboundStreamPayload`, `TryProtectAndAccountStreamApplicationPayload`, `TryProtectAndAccountApplicationPayloadOnPath`.
    - Flow: `QuicStream` serializes writes with a `SemaphoreSlim`, posts a runtime stream action, reserves flow-control capacity, builds a STREAM frame payload, protects it, accounts recovery, and emits a send-datagram effect.
    - Hot-path status: likely hot per response write.
    - Allocation/copy: stream data arrives as `ReadOnlyMemory<byte>` but the runtime builds `byte[]` stream payloads and protected packets.
    - Locks/queues: `QuicStream` write gate plus runtime event posting.
    - Batching opportunity: `QuicApplicationSendQueue` can batch delayed application sends, but tiny final writes may bypass delayed-send batching and emit immediately.

14. UDP send
    - Main files/classes/methods: `QuicListenerHost.ObserveEffect`, `SendDatagram`, `QuicConnectionSendDatagramEffect`.
    - Flow: shard effects are applied by the listener host. Send effects are sent over the UDP socket for the selected path.
    - Hot-path status: hot per protected packet.
    - Allocation/copy: protected packet is already a `byte[]`; socket send copies into OS networking.
    - Await/queue: send is effect-driven from the runtime shard. The inspected path suggests one send effect per protected packet.
    - Batching opportunity: UDP send batching is not visible in the inspected code.

## Plaintext And JSON Shared Path

`GET /plaintext` and `GET /json` share nearly the entire path above:

- same QUIC listener, packet receive, routing, protection, ACK/recovery, stream-state, and stream facade
- same HTTP/3 request parsing, QPACK decode, header validation, request object creation, and response write path
- same `TechEmpowerHandler.HandleAsync`, method/path dispatch, `Payload`, header list construction, date formatting, response object, HEADERS frame generation, DATA frame generation, stream write, packet protection, and UDP send path

The only meaningful differences in the sample handler are:

- `/plaintext` returns static `Hello, World!` bytes with `content-type: text/plain`
- `/json` returns static JSON bytes with `content-type: application/json`
- both bodies are already precomputed byte arrays in `TechEmpowerPayloads`

Because JSON serialization is not performed per request in this sample, the close plaintext/JSON benchmark results point at the shared QUIC/H3 request-response path rather than serializer cost.

## Diagnostic Notes

- The most suspicious shared categories are per-request/frame/header allocation, per-datagram copy, runtime channel scheduling, stream write/final-write packetization, and repeated response header/QPACK work.
- Some allocations are correctness-oriented ownership boundaries and may be acceptable. They should be measured before changing ownership.
- The first measurement should distinguish CPU, allocation/GC, queue/scheduler, stream-write, flush/send, and packet counts on the actual Incursa server process.
