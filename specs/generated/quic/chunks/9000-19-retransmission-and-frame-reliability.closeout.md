# 9000-19-retransmission-and-frame-reliability Closeout

## Audit Result
- `clean_with_explicit_blockers`
- In-scope requirements: 39 total, 2 implemented and tested, 25 partial, 12 blocked with explicit notes.
- Stale or wrong requirement IDs: none found.
- `src/Incursa.Quic/QuicPathValidation.cs` has no in-scope requirement refs; all trace refs are in `tests/` and use the correct IDs.
- No reconciliation artifact existed for this chunk; the implementation summary was treated as the starting point, but the live code/test audit reclassifies 25 requirements as partial rather than blocked.

## Requirements Completed
- `S13P3`: `REQ-QUIC-RFC9000-S13P3-0010`, `REQ-QUIC-RFC9000-S13P3-0027`

## Partially Covered Requirements
- REQ-QUIC-RFC9000-S13P3-0006, REQ-QUIC-RFC9000-S13P3-0007 - CRYPTO buffering/discard helpers exist in src/Incursa.Quic/QuicCryptoBuffer.cs, with coverage in tests/Incursa.Quic.Tests/QuicCryptoBufferTests.cs and tests/Incursa.Quic.Tests/QuicCryptoBufferFuzzTests.cs. There is no retransmission controller or packet-number-space discard policy.
- REQ-QUIC-RFC9000-S13P3-0008, REQ-QUIC-RFC9000-S13P3-0009 - STREAM parsing/formatting and RESET_STREAM framing exist in src/Incursa.Quic/QuicStreamParser.cs, src/Incursa.Quic/QuicStreamFrame.cs, and src/Incursa.Quic/QuicFrameCodec.cs, with tests in tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs, tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs, and tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs. No resend suppression or stream-lifecycle policy exists.
- REQ-QUIC-RFC9000-S13P3-0011, REQ-QUIC-RFC9000-S13P3-0012, REQ-QUIC-RFC9000-S13P3-0013 - RESET_STREAM and STOP_SENDING codecs exist in src/Incursa.Quic/QuicFrameCodec.cs, with round-trip and truncation tests in tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs and tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs. No retransmission-until-acknowledged loop exists.
- REQ-QUIC-RFC9000-S13P3-0015, REQ-QUIC-RFC9000-S13P3-0016 - MAX_DATA frame support exists in src/Incursa.Quic/QuicMaxDataFrame.cs and src/Incursa.Quic/QuicFrameCodec.cs, with fuzz coverage in tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs. No sender-side update-on-loss logic exists.
- REQ-QUIC-RFC9000-S13P3-0017, REQ-QUIC-RFC9000-S13P3-0018, REQ-QUIC-RFC9000-S13P3-0019 - MAX_STREAM_DATA frame support exists in src/Incursa.Quic/QuicMaxStreamDataFrame.cs and src/Incursa.Quic/QuicFrameCodec.cs, with fuzz coverage in tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs. No stream-lifecycle state suppresses further sends.
- REQ-QUIC-RFC9000-S13P3-0020, REQ-QUIC-RFC9000-S13P3-0021 - MAX_STREAMS frame support exists in src/Incursa.Quic/QuicMaxStreamsFrame.cs and src/Incursa.Quic/QuicFrameCodec.cs, with fuzz coverage in tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs. No resend/update scheduler exists.
- REQ-QUIC-RFC9000-S13P3-0022, REQ-QUIC-RFC9000-S13P3-0023, REQ-QUIC-RFC9000-S13P3-0024, REQ-QUIC-RFC9000-S13P3-0025 - Blocked-frame types and codecs exist in src/Incursa.Quic/QuicDataBlockedFrame.cs, src/Incursa.Quic/QuicStreamDataBlockedFrame.cs, src/Incursa.Quic/QuicStreamsBlockedFrame.cs, and src/Incursa.Quic/QuicFrameCodec.cs, with tests in tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs and tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs. The emission policy is still missing.
- REQ-QUIC-RFC9000-S13P3-0026 - PATH_CHALLENGE generation and path-validation padding helpers exist in src/Incursa.Quic/QuicPathValidation.cs and src/Incursa.Quic/QuicFrameCodec.cs, with tests in tests/Incursa.Quic.Tests/QuicPathValidationTests.cs and tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs. There is no periodic resend loop or liveness scheduler.
- REQ-QUIC-RFC9000-S13P3-0028 - PATH_RESPONSE framing exists in src/Incursa.Quic/QuicPathResponseFrame.cs and src/Incursa.Quic/QuicFrameCodec.cs, with tests in tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs and tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs. There is no one-shot send policy.
- REQ-QUIC-RFC9000-S13P3-0029, REQ-QUIC-RFC9000-S13P3-0030 - NEW_CONNECTION_ID and RETIRE_CONNECTION_ID framing exists in src/Incursa.Quic/QuicNewConnectionIdFrame.cs, src/Incursa.Quic/QuicRetireConnectionIdFrame.cs, and src/Incursa.Quic/QuicFrameCodec.cs, with tests in tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs and tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs. No connection-ID manager or retransmission policy exists.
- REQ-QUIC-RFC9000-S13P3-0031 - NEW_TOKEN framing exists in src/Incursa.Quic/QuicNewTokenFrame.cs and src/Incursa.Quic/QuicFrameCodec.cs, with fuzz coverage in tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs. There is no duplicate/reorder detection logic.
- REQ-QUIC-RFC9000-S13P3-0032 - PING/PADDING framing exists in src/Incursa.Quic/QuicFrameCodec.cs, with tests in tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs and tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs. The repo does not have a repair-policy layer for lost PING/PADDING packets.
- REQ-QUIC-RFC9000-S13P3-0035 - MAX_DATA parsing accepts any encoded value in src/Incursa.Quic/QuicFrameCodec.cs, and fuzz coverage exists in tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs. There is no stateful receiver comparison/update logic.

## Remaining Open Requirements
- REQ-QUIC-RFC9000-S13P3-0001, REQ-QUIC-RFC9000-S13P3-0002, REQ-QUIC-RFC9000-S13P3-0003, REQ-QUIC-RFC9000-S13P3-0004, REQ-QUIC-RFC9000-S13P3-0005 - No sender/recovery layer in src or tests; src/Incursa.Quic/QuicFrameCodec.cs only handles frame encode/decode, not whole-packet retransmission policy.
- REQ-QUIC-RFC9000-S13P3-0014 - No CONNECTION_CLOSE frame/type/sender surface anywhere under src or tests.
- REQ-QUIC-RFC9000-S13P3-0033, REQ-QUIC-RFC9000-S13P3-0034 - No HANDSHAKE_DONE surface and no retransmission-prioritization scheduler.
- REQ-QUIC-RFC9000-S13P3-0036, REQ-QUIC-RFC9000-S13P3-0037, REQ-QUIC-RFC9000-S13P3-0038, REQ-QUIC-RFC9000-S13P3-0039 - No loss-detection, acknowledged-data suppression, PTO/memory-limit discard, or congestion-control policy layer.

## Files Changed
- [REQUIREMENT-GAPS.md](C:/src/incursa/quic-dotnet/specs/requirements/quic/REQUIREMENT-GAPS.md)
- [QuicPathValidation.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPathValidation.cs)
- [QuicAckGenerationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs)
- [QuicFrameCodecTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs)
- [QuicFrameCodecFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs)
- [QuicPathValidationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicPathValidationTests.cs)
- [9000-19-retransmission-and-frame-reliability.implementation-summary.md](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.implementation-summary.md)
- [9000-19-retransmission-and-frame-reliability.implementation-summary.json](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9000-19-retransmission-and-frame-reliability.implementation-summary.json)

## Tests Reviewed
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicAckGenerationStateTests|FullyQualifiedName~QuicFrameCodecTests|FullyQualifiedName~QuicFrameCodecFuzzTests|FullyQualifiedName~QuicPathValidationTests"` -> `23 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj` -> `249 passed, 0 failed, 0 skipped`

## Reference Audit
- [src/Incursa.Quic/QuicPathValidation.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPathValidation.cs): no in-scope requirement refs, which is consistent with the repository convention for this slice.
- [tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs): uses `REQ-QUIC-RFC9000-S13P3-0010`.
- [tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs): uses `REQ-QUIC-RFC9000-S13P3-0010`.
- [tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs): uses `REQ-QUIC-RFC9000-S13P3-0010`.
- [tests/Incursa.Quic.Tests/QuicPathValidationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicPathValidationTests.cs): uses `REQ-QUIC-RFC9000-S13P3-0027`.
- No stale or wrong refs were found in the scoped source or tests.

## Risks Or Follow-Up Notes
- The implementation summary underreported existing helper-backed coverage; 25 requirements are partial rather than blocked because code/tests already prove part of the behavior.
- The remaining 12 blocked requirements still depend on missing packet-assembly, send-path batching, recovery timer, flow-control, path-validation lifecycle, connection-ID lifecycle, and congestion-control surfaces.
- The helper-level subset is intentionally narrow and does not claim the missing send/recovery semantics for the rest of S13P3.
