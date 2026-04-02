# RFC 9000 Chunk Reconciliation: `9000-01-streams-core`

## Scope

Source: `./specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S2, S2P1, S2P2, S2P3, S2P4`

## Status Summary

- implemented and tested: 8
- implemented but missing tests: 0
- tested but implementation mapping unclear: 10
- partially implemented: 1
- not implemented: 25
- unclear / needs human review: 0

## Requirements in Scope

### S2

- `REQ-QUIC-RFC9000-S2-0001` - not implemented; The repository does not expose an ordered application-facing stream abstraction.
- `REQ-QUIC-RFC9000-S2-0002` - not implemented; There is no connection or send-path surface that creates streams by writing data.
- `REQ-QUIC-RFC9000-S2-0003` - not implemented; No connection-scoped stream lifetime model exists.
- `REQ-QUIC-RFC9000-S2-0004` - not implemented; The parser classifies initiator bits, but it does not model endpoint-driven stream creation.
- `REQ-QUIC-RFC9000-S2-0005` - not implemented; No scheduler or multiplexing surface models interleaved concurrent stream transmission.
- `REQ-QUIC-RFC9000-S2-0006` - tested but implementation mapping unclear; RESET_STREAM and STOP_SENDING wire formats exist, but there is no stream lifecycle implementation behind them.
- `REQ-QUIC-RFC9000-S2-0007` - not implemented; There is no delivery layer that could enforce or expose cross-stream ordering semantics.
- `REQ-QUIC-RFC9000-S2-0008` - tested but implementation mapping unclear; MAX_STREAMS and related frame codecs exist, but no live stream manager operates concurrent streams.
- `REQ-QUIC-RFC9000-S2-0009` - tested but implementation mapping unclear; Flow-control-related frame codecs exist, but there is no sender-side enforcement or per-stream data accounting.

### S2P1

- `REQ-QUIC-RFC9000-S2P1-0001` - tested but implementation mapping unclear; Stream-ID classification shows unidirectional types, but no data-path enforcement restricts direction.
- `REQ-QUIC-RFC9000-S2P1-0002` - tested but implementation mapping unclear; Stream-ID classification shows bidirectional types, but no bidirectional send/receive surface exists.
- `REQ-QUIC-RFC9000-S2P1-0003` - implemented and tested; `QuicStreamId` and `TryParseStreamIdentifier` expose stream IDs as first-class values.
- `REQ-QUIC-RFC9000-S2P1-0004` - implemented and tested; Stream IDs are parsed through the shared QUIC varint helper and bounded by the 62-bit QUIC varint ceiling.
- `REQ-QUIC-RFC9000-S2P1-0005` - not implemented; No connection-scoped stream registry enforces uniqueness.
- `REQ-QUIC-RFC9000-S2P1-0006` - implemented and tested; Stream IDs are encoded and parsed as QUIC variable-length integers.
- `REQ-QUIC-RFC9000-S2P1-0007` - not implemented; No stream allocation or reuse prevention surface exists.
- `REQ-QUIC-RFC9000-S2P1-0008` - implemented and tested; The least significant bit is exposed as initiator classification.
- `REQ-QUIC-RFC9000-S2P1-0009` - implemented and tested; Even-valued stream IDs classify as client-initiated.
- `REQ-QUIC-RFC9000-S2P1-0010` - implemented and tested; Odd-valued stream IDs classify as server-initiated.
- `REQ-QUIC-RFC9000-S2P1-0011` - implemented and tested; The second least significant bit is exposed as bidirectional versus unidirectional classification.
- `REQ-QUIC-RFC9000-S2P1-0012` - not implemented; No stream ID allocator establishes the per-type minimum starting points.
- `REQ-QUIC-RFC9000-S2P1-0013` - not implemented; No stream ID allocator enforces monotonic creation.
- `REQ-QUIC-RFC9000-S2P1-0014` - not implemented; No stream manager opens lower-numbered streams when IDs arrive out of order.

### S2P2

- `REQ-QUIC-RFC9000-S2P2-0001` - implemented and tested; STREAM frame parsing and formatting preserve stream payload bytes.
- `REQ-QUIC-RFC9000-S2P2-0002` - partially implemented; STREAM frames expose Stream ID and Offset fields, but no ordered reassembly layer places data for delivery.
- `REQ-QUIC-RFC9000-S2P2-0003` - not implemented; No application-facing ordered byte-stream delivery surface exists.
- `REQ-QUIC-RFC9000-S2P2-0004` - not implemented; No out-of-order buffering or flow-control-bounded reassembly exists.
- `REQ-QUIC-RFC9000-S2P2-0005` - not implemented; No optional out-of-order delivery API exists.
- `REQ-QUIC-RFC9000-S2P2-0006` - not implemented; No receive-state implementation can discard already-received data.
- `REQ-QUIC-RFC9000-S2P2-0007` - not implemented; No retransmission/send-state surface ensures byte stability at offsets.
- `REQ-QUIC-RFC9000-S2P2-0008` - not implemented; No conflicting-retransmission detection or error path exists.
- `REQ-QUIC-RFC9000-S2P2-0009` - tested but implementation mapping unclear; The parser exposes stream payload as opaque bytes, but there is no higher-level stream abstraction to prove the API shape.
- `REQ-QUIC-RFC9000-S2P2-0010` - not implemented; No sender-side flow-control enforcement exists.

### S2P3

- `REQ-QUIC-RFC9000-S2P3-0001` - not implemented; The repository has no stream scheduling or prioritization interface.
- `REQ-QUIC-RFC9000-S2P3-0002` - not implemented; The repository has no application-visible priority controls.
- `REQ-QUIC-RFC9000-S2P3-0003` - not implemented; The repository has no resource allocator that consumes stream priority information.

### S2P4

- `REQ-QUIC-RFC9000-S2P4-0001` - not implemented; No application-facing stream interface exists.
- `REQ-QUIC-RFC9000-S2P4-0002` - not implemented; No application-facing stream interface exists to constrain or subset.
- `REQ-QUIC-RFC9000-S2P4-0003` - not implemented; No write API or flow-credit reservation surface exists.
- `REQ-QUIC-RFC9000-S2P4-0004` - tested but implementation mapping unclear; STREAM frame FIN support exists at the codec layer, but no stream API exposes clean termination.
- `REQ-QUIC-RFC9000-S2P4-0005` - tested but implementation mapping unclear; RESET_STREAM frame support exists at the codec layer, but no stream API exposes abrupt reset semantics.
- `REQ-QUIC-RFC9000-S2P4-0006` - tested but implementation mapping unclear; STREAM parsing exposes readable payload bytes, but no stream API models application reads.
- `REQ-QUIC-RFC9000-S2P4-0007` - tested but implementation mapping unclear; STOP_SENDING frame support exists at the codec layer, but no stream API models aborting reads.
- `REQ-QUIC-RFC9000-S2P4-0008` - not implemented; No notification or callback surface exists for stream state changes.

## Existing Implementation Evidence

- `src/Incursa.Quic/QuicStreamId.cs:6-43`
- `src/Incursa.Quic/QuicStreamParser.cs:11-111`
- `src/Incursa.Quic/QuicStreamFrame.cs:6-93`
- `src/Incursa.Quic/QuicVariableLengthInteger.cs:6-129`
- `src/Incursa.Quic/QuicFrameCodec.cs:235-317`
- `src/Incursa.Quic/QuicFrameCodec.cs:388-440`
- `src/Incursa.Quic/QuicFrameCodec.cs:616-687`
- `benchmarks/QuicStreamParsingBenchmarks.cs:9-70`

## Existing Test Evidence

- `tests/Incursa.Quic.Tests/QuicStreamIdTests.cs:15-74`
- `tests/Incursa.Quic.Tests/QuicStreamIdPropertyTests.cs:7-28`
- `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs:7-419`
- `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs:35-95`
- `tests/Incursa.Quic.Tests/QuicVariableLengthIntegerTests.cs:45-164`
- `tests/Incursa.Quic.Tests/QuicVariableLengthIntegerPropertyTests.cs:7-20`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs:231-316`
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs:134-197`
- `tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs:6-117`
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs:5-95`

## Generated Inputs Consulted

- `docs/requirements-workflow.md`
- `specs/generated/quic/import-audit-summary.md`
- `specs/generated/quic/import-audit-details.json`
- `specs/generated/quic/quic-existing-work-inventory.md`
- `specs/generated/quic/quic-existing-work-inventory.json`
- `specs/generated/quic/implementation-chunk-manifest.md`
- `specs/generated/quic/9000.assembly-map.json`
- `specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- `specs/requirements/quic/REQUIREMENT-GAPS.md`
- `specs_old/requirements/quic/SPEC-QUIC-STRM.md`
- `specs/generated/quic/chunks/9000-26-frame-encodings-part-3.reconciliation.md`

## Old -> New Requirement ID Mappings Applied

- Rewrote the remaining legacy stream-ID test traits in `tests/Incursa.Quic.Tests/QuicStreamIdTests.cs` and `tests/Incursa.Quic.Tests/QuicStreamIdPropertyTests.cs`.
- Applied these clear mappings:
  - `REQ-QUIC-STRM-0001` -> `REQ-QUIC-RFC9000-S2P1-0003`, `REQ-QUIC-RFC9000-S2P1-0004`, `REQ-QUIC-RFC9000-S2P1-0006`
  - `REQ-QUIC-STRM-0002` -> `REQ-QUIC-RFC9000-S2P1-0008`, `REQ-QUIC-RFC9000-S2P1-0009`, `REQ-QUIC-RFC9000-S2P1-0010`
  - `REQ-QUIC-STRM-0003` -> `REQ-QUIC-RFC9000-S2P1-0011`
  - `REQ-QUIC-STRM-0004` -> `REQ-QUIC-RFC9000-S2P1-0008`, `REQ-QUIC-RFC9000-S2P1-0009`, `REQ-QUIC-RFC9000-S2P1-0010`, `REQ-QUIC-RFC9000-S2P1-0011`

## Gaps Fixed in This Pass

- Replaced the last live `REQ-QUIC-STRM-0001` through `REQ-QUIC-STRM-0004` traits in the stream-ID test suite with canonical RFC 9000 Section 2.1 IDs.
- Added `TryParseStreamIdentifier_AcceptsTheMaximumRepresentableStreamId` to prove the 62-bit stream-ID ceiling through the stream parser surface rather than only through the shared varint tests.
- Kept the pass local to the selected chunk plus the already-existing shared varint helper evidence.

## Remaining Gaps

- The repository still has no stream state machine, stream allocator, or connection-scoped stream registry for `S2`, `S2P1-0005`, `S2P1-0007`, and `S2P1-0012` through `S2P1-0014`.
- The repository still has no ordered stream reassembly or buffering layer for `S2P2-0002` through `S2P2-0010`.
- The repository still has no prioritization surface for `S2P3-0001` through `S2P3-0003`.
- The repository still has no application-facing stream interface for `S2P4-0001` through `S2P4-0003` and `S2P4-0008`.
- In-scope `S2-0006`, `S2-0008`, `S2-0009`, `S2P1-0001`, `S2P1-0002`, `S2P2-0009`, and `S2P4-0004` through `S2P4-0007` have adjacent wire-level evidence only; they still need a stateful stream implementation to become fully proven.

## Requirements Needing Deeper Implementation Work

- `REQ-QUIC-RFC9000-S2-0001` through `REQ-QUIC-RFC9000-S2-0005`
- `REQ-QUIC-RFC9000-S2-0007`
- `REQ-QUIC-RFC9000-S2P1-0005`
- `REQ-QUIC-RFC9000-S2P1-0007`
- `REQ-QUIC-RFC9000-S2P1-0012` through `REQ-QUIC-RFC9000-S2P1-0014`
- `REQ-QUIC-RFC9000-S2P2-0002` through `REQ-QUIC-RFC9000-S2P2-0010`
- `REQ-QUIC-RFC9000-S2P3-0001` through `REQ-QUIC-RFC9000-S2P3-0003`
- `REQ-QUIC-RFC9000-S2P4-0001` through `REQ-QUIC-RFC9000-S2P4-0003`
- `REQ-QUIC-RFC9000-S2P4-0008`

## Tests Run and Results

- Stream slice: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicStream"`
- Passed: 30
- Failed: 0
- Skipped: 0
- Duration: 122 ms
- Full suite: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
- Passed: 295
- Failed: 0
- Skipped: 0
- Duration: 204 ms

## Notes

- `specs/requirements/quic/REQUIREMENT-GAPS.md` exists and did not need a new entry for this pass because the remaining gaps are already cleanly attributable to missing stateful stream surfaces rather than an ambiguous requirement import.
- The permanent benchmark coverage for the live parser hot path already exists in `benchmarks/QuicStreamParsingBenchmarks.cs`; this reconciliation pass did not need to add another benchmark.
