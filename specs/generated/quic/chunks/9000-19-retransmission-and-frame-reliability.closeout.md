# 9000-19-retransmission-and-frame-reliability Closeout

## Audit Result
- `clean_with_explicit_blockers`
- In-scope requirements: 39 total, 2 implemented and tested, 25 partial, 12 blocked with explicit notes.
- Stale or wrong requirement IDs: none found.
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S13P3-0010.cs` and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S13P3-0027.cs` provide the helper-backed subset that is now closed.
- The remaining 25 helper-backed clauses are still partial rather than blocked because the repository has frame/state helpers but not the sender/recovery orchestration that would make the behavior complete.

## Requirements Completed
- `S13P3`: `REQ-QUIC-RFC9000-S13P3-0010`, `REQ-QUIC-RFC9000-S13P3-0027`

## Partially Covered Requirements
- `REQ-QUIC-RFC9000-S13P3-0006`, `REQ-QUIC-RFC9000-S13P3-0007` - CRYPTO buffering/discard helpers exist in `src/Incursa.Quic/QuicCryptoBuffer.cs` and are exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S4-0005.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S7P5-0004.cs`, and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P6-0004.cs`; there is still no sender/recovery controller or packet-number-space discard policy.
- `REQ-QUIC-RFC9000-S13P3-0008`, `REQ-QUIC-RFC9000-S13P3-0009` - STREAM parsing/formatting helpers exist in `src/Incursa.Quic/QuicFrameCodec.cs` and are exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P8-0001.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P8-0002.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P8-0004.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P8-0005.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P8-0018.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P8-0019.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P8-0020.cs`, and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P4-0008.cs`; no resend suppression or stream-lifecycle policy exists.
- `REQ-QUIC-RFC9000-S13P3-0011`, `REQ-QUIC-RFC9000-S13P3-0012`, `REQ-QUIC-RFC9000-S13P3-0013` - RESET_STREAM and STOP_SENDING codecs exist in `src/Incursa.Quic/QuicFrameCodec.cs` and are exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P4-0008.cs` and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P5-0008.cs`; no retransmission-until-acknowledged loop exists.
- `REQ-QUIC-RFC9000-S13P3-0015`, `REQ-QUIC-RFC9000-S13P3-0016` - MAX_DATA support exists in `src/Incursa.Quic/QuicMaxDataFrame.cs` and is exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P9-0002.cs`; no sender-side update-on-loss logic exists.
- `REQ-QUIC-RFC9000-S13P3-0017`, `REQ-QUIC-RFC9000-S13P3-0018`, `REQ-QUIC-RFC9000-S13P3-0019` - MAX_STREAM_DATA support exists in `src/Incursa.Quic/QuicMaxStreamDataFrame.cs` and is exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P10-0005.cs`; no stream-lifecycle state suppresses further sends.
- `REQ-QUIC-RFC9000-S13P3-0020`, `REQ-QUIC-RFC9000-S13P3-0021` - MAX_STREAMS support exists in `src/Incursa.Quic/QuicMaxStreamsFrame.cs` and is exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P11-0001.cs`; no resend/update scheduler exists.
- `REQ-QUIC-RFC9000-S13P3-0022`, `REQ-QUIC-RFC9000-S13P3-0023`, `REQ-QUIC-RFC9000-S13P3-0024`, `REQ-QUIC-RFC9000-S13P3-0025` - DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED codecs exist in `src/Incursa.Quic/QuicDataBlockedFrame.cs`, `src/Incursa.Quic/QuicStreamDataBlockedFrame.cs`, `src/Incursa.Quic/QuicStreamsBlockedFrame.cs`, and are exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P12-0003.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P13-0003.cs`, and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P14-0002.cs`; emission policy is still missing.
- `REQ-QUIC-RFC9000-S13P3-0026` - PATH_CHALLENGE generation and path-validation helpers exist in `src/Incursa.Quic/QuicPathValidation.cs` and are exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P17-0002.cs` and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P17-0003.cs`; there is no periodic resend loop or liveness scheduler.
- `REQ-QUIC-RFC9000-S13P3-0028` - PATH_RESPONSE handling exists in `src/Incursa.Quic/QuicPathResponseFrame.cs` and is exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S8P2P2-0001.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S8P2P2-0005.cs`, and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S8P2P2-0006.cs`; there is no one-shot send policy.
- `REQ-QUIC-RFC9000-S13P3-0029`, `REQ-QUIC-RFC9000-S13P3-0030` - NEW_CONNECTION_ID and RETIRE_CONNECTION_ID framing exists in `src/Incursa.Quic/QuicNewConnectionIdFrame.cs`, `src/Incursa.Quic/QuicRetireConnectionIdFrame.cs`, and is exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P15-0008.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P15-0011.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P15-0019.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P16-0004.cs`, and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P16-0005.cs`; no connection-ID manager or retransmission policy exists.
- `REQ-QUIC-RFC9000-S13P3-0031` - NEW_TOKEN framing exists in `src/Incursa.Quic/QuicNewTokenFrame.cs` and is exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P7-0004.cs`; there is no duplicate/reorder detection logic.
- `REQ-QUIC-RFC9000-S13P3-0032` - PING/PADDING framing exists in `src/Incursa.Quic/QuicFrameCodec.cs` and is exercised by `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P1-0001.cs` and `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P2-0002.cs`; the repo does not have a repair-policy layer for lost PING/PADDING packets.
- `REQ-QUIC-RFC9000-S13P3-0035` - MAX_DATA parsing accepts any encoded value in `src/Incursa.Quic/QuicFrameCodec.cs`, and fuzz coverage exists in `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/REQ-QUIC-RFC9000-S19P9-0002.cs`; there is no stateful receiver comparison/update logic.

## Remaining Open Requirements
- `REQ-QUIC-RFC9000-S13P3-0001` through `REQ-QUIC-RFC9000-S13P3-0005` - no sender/recovery layer in `src` or `tests`; `src/Incursa.Quic/QuicFrameCodec.cs` only handles frame encode/decode, not whole-packet retransmission policy.
- `REQ-QUIC-RFC9000-S13P3-0014` - no `CONNECTION_CLOSE` frame/type/sender surface anywhere under `src` or `tests`.
- `REQ-QUIC-RFC9000-S13P3-0033`, `REQ-QUIC-RFC9000-S13P3-0034` - no `HANDSHAKE_DONE` surface and no retransmission-prioritization scheduler.
- `REQ-QUIC-RFC9000-S13P3-0036` through `REQ-QUIC-RFC9000-S13P3-0039` - no loss-detection, acknowledged-data suppression, PTO/memory-limit discard, or congestion-control policy layer.

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
