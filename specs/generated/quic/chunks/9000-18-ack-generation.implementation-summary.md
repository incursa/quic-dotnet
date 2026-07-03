# 9000-18-ack-generation Implementation Summary

## Requirements Completed
- `REQ-QUIC-RFC9000-S13P1-0003`
- `REQ-QUIC-RFC9000-0753`
- `REQ-QUIC-RFC9000-S13P2-0002`
- `REQ-QUIC-RFC9000-S13P2-0003`
- `RFC9000-S13-2-P2-R01`
- `REQ-QUIC-RFC9000-S13P2P1-0001`
- `REQ-QUIC-RFC9000-0758`
- `RFC9000-S13-2-1-P2-R02`
- `RFC9000-S13-2-1-P2-R01`
- `REQ-QUIC-RFC9000-S13P2P1-0006`
- `REQ-QUIC-RFC9000-S13P2P1-0007`
- `REQ-QUIC-RFC9000-S13P2P1-0008`
- `RFC9000-S13-2-1-P5-S1-R01`
- `RFC9000-S13-2-1-P5-S2-R01`
- `REQ-QUIC-RFC9000-S13P2P1-0013`
- `REQ-QUIC-RFC9000-1322`
- `REQ-QUIC-RFC9000-S13P2P2-0001`
- `RFC9000-S13-2-2-P4-S1-R01`
- `RFC9000-S13-2-2-P5-S1-R01`
- `REQ-QUIC-RFC9000-S13P2P3-0001`
- `REQ-QUIC-RFC9000-13230`
- `REQ-QUIC-RFC9000-S13P2P3-0003`
- `REQ-QUIC-RFC9000-13233`
- `REQ-QUIC-RFC9000-13235`
- `REQ-QUIC-RFC9000-S13P2P3-0008`
- `REQ-QUIC-RFC9000-13236`
- `RFC9000-S13-2-3-P5-S1-R01`
- `REQ-QUIC-RFC9000-S13P2P3-0011`
- `RFC9000-S13-2-3-P7-S1-R01`
- `RFC9000-S13-2-5-P2-S3-R01`
- `REQ-QUIC-RFC9000-S13P2P5-0001`
- `REQ-QUIC-RFC9000-S13P2P5-0002`
- `RFC9000-S13-2-5-P2-S2-R01`
- `REQ-QUIC-RFC9000-S13P2P5-0005`
- `RFC9000-S13-2-6-P1-S1-R01`
- `RFC9000-S13-2-6-P1-S2-R01`

## Files Changed
- `src/Incursa.Quic/QuicPacketNumberSpace.cs`
- `src/Incursa.Quic/QuicAckGenerationState.cs`
- `src/Incursa.Quic/QuicCongestionControlState.cs`
- `src/Incursa.Quic/PublicAPI.Unshipped.txt`
- `tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`
- `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`
- `tests/Incursa.Quic.Tests/RequirementHomes/RFC9000/RFC9000-S13-2-5-P2-S3-R01.cs`

## Tests Added or Updated
- Added or updated `TryBuildAckFrame_RoundsTripProcessedPacketsAndReportsAckDelay`.
- Added or updated `ShouldSendAckImmediately_ForInitialAndHandshakePackets`.
- Added or updated `ShouldSendAckImmediately_ForOutOfOrderAndCePackets`.
- Added or updated `ShouldDelayAckUntilSecondAckElicitingPacketOrMaxAckDelay`.
- Added or updated `CanSendOnlyOneAckOnlyPacketPerAckElicitingPacket`.
- Added or updated `TryBuildAckFrame_TrimsOldestRangesWhenLimitReached`.
- Added or updated `PacketNumberSpaces_AreTrackedIndependently`.
- Added or updated `TryBuildAckFrame_UsesEcnCountsAndReportsMeasuredDelayWhenDelayed`.
- Added or updated `TryParseAckFrame_RoundTripsRangesAndEcnCounts`.
- Added or updated `Fuzz_FrameCodec_RoundTripsRepresentativeFrameShapesAndRejectsTruncation`.
- Added or updated `TryBuildAckFrame_IncludesBufferingDelayFromUnavailableDecryptionKeys` and `TryBuildAckFrame_DoesNotInventBufferingDelayWhenNoneWasRecorded`.

## Tests Run and Results
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicAckGenerationStateTests|FullyQualifiedName~QuicFrameCodecTests|FullyQualifiedName~QuicFrameCodecFuzzTests"`
- Result: `18 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj`
- Result: `249 passed, 0 failed, 0 skipped`

## Remaining Open Requirements In Scope
### Deferred
- `REQ-QUIC-RFC9000-S13P2P3-0006` - Informational prose about expected ACK receipt rates; no executable behavior is attached to the clause.
- `REQ-QUIC-RFC9000-S13P2P3-0013` - Section marker / descriptive clause for Section 13.2.4, not a runtime rule.
- `REQ-QUIC-RFC9000-S13P2P4-0001` - Informational note about ACK frame loss and reordering; no helper-level behavior can guarantee or violate it directly.
- `REQ-QUIC-RFC9000-S13P2P6-0004` - Informational consequence of delayed or lost server handshake messages; no separate implementation surface exists for the note itself.
### Blocked
- `REQ-QUIC-RFC9000-S13-0001` - There is no packet-assembly surface that can guarantee one or more frames in every QUIC packet.
- `RFC9000-S13-P2-S2-R01` - There is no send-path batching scheduler that can wait briefly to coalesce frames before emitting an underfilled packet.
- `RFC9000-S13-P2-S3-R01` - There is no heuristic-based packet pacing surface that can decide how long to wait before sending.
- `REQ-QUIC-RFC9000-S13-0004` - There is no packet composer that can pack multiple STREAM frames into one QUIC packet.
- `REQ-QUIC-RFC9000-S13-0005` - There is no packet packing policy that can prefer fewer active streams while preserving transmission efficiency.
- `REQ-QUIC-RFC9000-0749` - There is no decryption-complete / frame-processing completion hook that can delay ACKing until all packet contents are processed.
- `REQ-QUIC-RFC9000-S13P1-0002` - There is no STREAM enqueue / delivery lifecycle surface to distinguish application enqueue from app-consumption.
- `RFC9000-S13-1-P3-R01` - There is no incoming-ACK validation surface that can raise PROTOCOL_VIOLATION for acknowledgments of unsent packets.
- `REQ-QUIC-RFC9000-S13P2P1-0003` - There is no recovery timer surface that uses the receiver max_ack_delay in PTO or retransmission timeout calculations.
- `REQ-QUIC-RFC9000-S13P2P1-0009` - There is no peer-side ACK reception model to show that ACK-only traffic will not itself be acknowledged.
- `REQ-QUIC-RFC9000-S13P2P1-0012` - There is no feedback-loop model for adding ack-eliciting frames to otherwise non-ack-eliciting packets.
- `REQ-QUIC-RFC9000-13234` - There is no peer-ACK lifecycle surface to retire ACK ranges after acknowledgments for an ACK frame are received.
- `REQ-QUIC-RFC9000-S13P2P6-0003` - There is no carrier-selection surface that can force client 0-RTT acknowledgments onto 1-RTT packets.
- `RFC9000-S13-2-7-P1-S3-R01` - There is no periodic non-PADDING probe / send-ack-eliciting-frames scheduler.

## Risks or Follow-up Notes
- The implementation is helper-level and does not yet own packet assembly, recovery timers, peer ACK validation, or carrier selection for 0-RTT versus 1-RTT acknowledgment delivery.
- ACK range trimming is bounded by `maximumRetainedAckRanges`; the peer-ACK lifecycle needed to retire ranges after received acknowledgments is still missing.
- No reconciliation artifact existed for this chunk when the earlier slice landed, so the work was treated as greenfield and the remaining gaps were left explicit rather than inferred. The follow-on proof for `RFC9000-S13-2-5-P2-S3-R01` now closes the decryption-key buffering-delay gap without changing the explicit blocker set.
