# 9000-15-error-handling Implementation Summary

## Requirements Completed

- Connection-close wire support for signaling connection-wide errors: `REQ-QUIC-RFC9000-S11-0001`, `REQ-QUIC-RFC9000-S11-0002`, `REQ-QUIC-RFC9000-S11-0003`, `REQ-QUIC-RFC9000-S11-0004`
- CONNECTION_CLOSE frame type selection and parsing for transport/application closes: `REQ-QUIC-RFC9000-S11P1-0001`, `REQ-QUIC-RFC9000-S11P1-0002`, `REQ-QUIC-RFC9000-S11P1-0003`
- Connection-close non-ack-eliciting classification fix for application closes: `REQ-QUIC-RFC9000-S11P1-0001`

## Files Changed

- `src/Incursa.Quic/QuicConnectionCloseFrame.cs`
- `src/Incursa.Quic/QuicFrameCodec.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingFuzzTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameTestData.cs`
- `specs/generated/quic/chunks/9000-15-error-handling.implementation-summary.md`
- `specs/generated/quic/chunks/9000-15-error-handling.implementation-summary.json`

## Tests Added Or Updated

- Added `tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingTests.cs` for transport/application CONNECTION_CLOSE round trips and invalid input rejection.
- Added `tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingFuzzTests.cs` for randomized CONNECTION_CLOSE round trips and truncation rejection.
- Updated `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs` so `IsAckElicitingFrameType` treats application CONNECTION_CLOSE (`0x1d`) as non-ack-eliciting.
- Updated `tests/Incursa.Quic.Tests/QuicFrameTestData.cs` with a CONNECTION_CLOSE frame builder.

## Tests Run And Results

- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicFrameCodecTests|FullyQualifiedName~QuicFrameCodecErrorHandlingTests|FullyQualifiedName~QuicFrameCodecErrorHandlingFuzzTests"`
  - Result: passed, 23 tests passed, 0 failed, 0 skipped.
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
  - Result: passed, 320 tests passed, 0 failed, 0 skipped.

## Remaining Open Requirements In Scope

- `REQ-QUIC-RFC9000-S11-0005`
- `REQ-QUIC-RFC9000-S11P1-0004`
- `REQ-QUIC-RFC9000-S11P1-0005`
- `REQ-QUIC-RFC9000-S11P1-0006`
- `REQ-QUIC-RFC9000-S11P1-0007`
- `REQ-QUIC-RFC9000-S11P1-0008`
- `REQ-QUIC-RFC9000-S11P2-0001`
- `REQ-QUIC-RFC9000-S11P2-0002`
- `REQ-QUIC-RFC9000-S11P2-0003`
- `REQ-QUIC-RFC9000-S11P2-0004`
- `REQ-QUIC-RFC9000-S11P2-0005`

## Risks Or Follow-up Notes

- The new CONNECTION_CLOSE codec closes the wire-format gap, but the endpoint lifecycle requirements still need a connection-state machine, terminal packet retransmission policy, and receive-path rollback support.
- `REQ-QUIC-RFC9000-S11P2-*` remains blocked by the missing application-protocol abstraction for instigating stream termination and handling STOP_SENDING-driven RESET_STREAM behavior.
- The repository now rejects application CONNECTION_CLOSE frames as ack-eliciting, which aligns the classifier with RFC 9000 error-handling semantics.
