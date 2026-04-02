# RFC 9002 Chunk Implementation Summary: `9002-03-loss-detection`

## Scope
- RFC: `9002`
- Section tokens: `S6`, `S6P1`, `S6P1P1`, `S6P1P2`, `S6P2`, `S6P2P1`, `S6P2P2`, `S6P2P2P1`, `S6P2P3`, `S6P2P4`, `S6P3`, `S6P4`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`
- Reconciliation artifact: not present in the repo

## Requirements Completed
- S6P1:
  - `REQ-QUIC-RFC9002-S6P1-0001` Declare loss only for packets that satisfy the basic loss criteria
- S6P1P1:
  - `REQ-QUIC-RFC9002-S6P1P1-0001` Recommend a packet threshold of three
  - `REQ-QUIC-RFC9002-S6P1P1-0002` Avoid packet thresholds below three
- S6P1P2:
  - `REQ-QUIC-RFC9002-S6P1P2-0001` Declare earlier packets lost after sufficient time
  - `REQ-QUIC-RFC9002-S6P1P2-0002` Bound the time threshold by timer granularity
  - `REQ-QUIC-RFC9002-S6P1P2-0003` Compute the time threshold from RTT and granularity
  - `REQ-QUIC-RFC9002-S6P1P2-0004` Schedule a timer for the remaining time before declaring loss
  - `REQ-QUIC-RFC9002-S6P1P2-0005` Use the recommended packet-threshold multiplier
  - `REQ-QUIC-RFC9002-S6P1P2-0006` Use a one-millisecond timer granularity
- S6P2:
  - `REQ-QUIC-RFC9002-S6P2-0002` Compute PTO per packet number space
- S6P2P1:
  - `REQ-QUIC-RFC9002-S6P2P1-0001` Schedule PTO after ack-eliciting transmission
  - `REQ-QUIC-RFC9002-S6P2P1-0002` Set max_ack_delay to zero for early handshake spaces
  - `REQ-QUIC-RFC9002-S6P2P1-0003` Keep PTO above granularity
  - `REQ-QUIC-RFC9002-S6P2P1-0004` Use the earlier PTO across Initial and Handshake spaces
  - `REQ-QUIC-RFC9002-S6P2P1-0005` Defer application-data PTO until handshake confirmation
  - `REQ-QUIC-RFC9002-S6P2P1-0007` Increase PTO backoff on timeout
  - `REQ-QUIC-RFC9002-S6P2P1-0010` Avoid conflicting timers
- S6P2P2:
  - `REQ-QUIC-RFC9002-S6P2P2-0001` Reuse prior-smoothed RTT on resumed connections
  - `REQ-QUIC-RFC9002-S6P2P2-0002` Default initial RTT to 333 milliseconds
  - `REQ-QUIC-RFC9002-S6P2P2-0003` Use PATH_CHALLENGE and PATH_RESPONSE timing for initial RTT
  - `REQ-QUIC-RFC9002-S6P2P2-0004` Do not treat PATH_CHALLENGE/PATH_RESPONSE delay as an RTT sample
- S6P3:
  - `REQ-QUIC-RFC9002-S6P3-0004` Permit RTT estimation from Retry timing
  - `REQ-QUIC-RFC9002-S6P3-0005` Allow using Retry-derived RTT as the initial RTT

## Files Changed
- [src/Incursa.Quic/QuicRecoveryTiming.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicRecoveryTiming.cs)
- [src/Incursa.Quic/QuicPathValidation.cs](C:/src/incursa/quic-dotnet/src/Incursa.Quic/QuicPathValidation.cs)
- [src/Incursa.Quic/PublicAPI.Unshipped.txt](C:/src/incursa/quic-dotnet/src/Incursa.Quic/PublicAPI.Unshipped.txt)
- [tests/Incursa.Quic.Tests/QuicPathValidationTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicPathValidationTests.cs)
- [tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs)
- [tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs)
- [specs/generated/quic/chunks/9002-03-loss-detection.implementation-summary.md](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9002-03-loss-detection.implementation-summary.md)
- [specs/generated/quic/chunks/9002-03-loss-detection.implementation-summary.json](C:/src/incursa/quic-dotnet/specs/generated/quic/chunks/9002-03-loss-detection.implementation-summary.json)

## Tests Added Or Updated
- [`tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs)
- [`tests/Incursa.Quic.Tests/QuicPathValidationTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicPathValidationTests.cs)
- [`tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs`](C:/src/incursa/quic-dotnet/tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs)

## Tests Run
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicRecoveryTimingTests|FullyQualifiedName~QuicPathValidationTests|FullyQualifiedName~QuicRttEstimatorTests"` -> `36 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj` -> `294 passed, 0 failed, 0 skipped`

## Remaining Open Requirements In Scope
- S6:
  - `REQ-QUIC-RFC9002-S6-0001` Separate loss detection by packet number space
- S6P1:
  - `REQ-QUIC-RFC9002-S6P1-0002` Allow smaller initial reordering thresholds with adaptation
- S6P1P2:
  - `REQ-QUIC-RFC9002-S6P1P2-0007` Allow alternative time-threshold experiments
- S6P2:
  - `REQ-QUIC-RFC9002-S6P2-0001` Send probe datagrams on PTO expiration or address-validation uncertainty
  - `REQ-QUIC-RFC9002-S6P2-0003` Do not infer loss from PTO expiration
- S6P2P1:
  - `REQ-QUIC-RFC9002-S6P2P1-0006` Restart PTO on send, acknowledgment, or key discard
  - `REQ-QUIC-RFC9002-S6P2P1-0008` Reset PTO backoff on acknowledgment
  - `REQ-QUIC-RFC9002-S6P2P1-0009` Suppress PTO-backoff reset on unvalidated Initial acknowledgments
- S6P2P2:
  - `REQ-QUIC-RFC9002-S6P2P2-0005` Reset timers when keys are discarded
- S6P2P2P1:
  - `REQ-QUIC-RFC9002-S6P2P2P1-0001` Delay server PTO until address validation traffic arrives
  - `REQ-QUIC-RFC9002-S6P2P2P1-0002` Reset the server PTO when the client sends data
  - `REQ-QUIC-RFC9002-S6P2P2P1-0003` Fire a past-due PTO immediately
  - `REQ-QUIC-RFC9002-S6P2P2P1-0004` Arm the client PTO before handshake confirmation
  - `REQ-QUIC-RFC9002-S6P2P2P1-0005` Send Handshake probes when keys are available
  - `REQ-QUIC-RFC9002-S6P2P2P1-0006` Send Initial probes otherwise
- S6P2P3:
  - `REQ-QUIC-RFC9002-S6P2P3-0001` Permit early CRYPTO probes for handshake speedup
- S6P2P4:
  - `REQ-QUIC-RFC9002-S6P2P4-0001` Probe with at least one ack-eliciting packet
  - `REQ-QUIC-RFC9002-S6P2P4-0002` Allow two full-sized PTO datagrams
  - `REQ-QUIC-RFC9002-S6P2P4-0003` Keep PTO probe packets ack-eliciting
  - `REQ-QUIC-RFC9002-S6P2P4-0004` Use other packet number spaces for PTO probes
  - `REQ-QUIC-RFC9002-S6P2P4-0005` Include new data in PTO probes
  - `REQ-QUIC-RFC9002-S6P2P4-0006` Allow previously sent data in PTO probes
  - `REQ-QUIC-RFC9002-S6P2P4-0007` Allow alternative probe-content strategies
  - `REQ-QUIC-RFC9002-S6P2P4-0008` Send a PING when no probe data exists
  - `REQ-QUIC-RFC9002-S6P2P4-0009` Allow declaring in-flight packets lost instead of probing
- S6P3:
  - `REQ-QUIC-RFC9002-S6P3-0001` Reject Retry as an acknowledgment
  - `REQ-QUIC-RFC9002-S6P3-0002` Reset recovery and congestion state on Retry
  - `REQ-QUIC-RFC9002-S6P3-0003` Retain cryptographic handshake state across Retry
- S6P4:
  - `REQ-QUIC-RFC9002-S6P4-0001` Discard recovery state when protection keys go away
  - `REQ-QUIC-RFC9002-S6P4-0002` Remove discarded packets from bytes in flight
  - `REQ-QUIC-RFC9002-S6P4-0003` Discard recovery state for rejected 0-RTT packets
  - `REQ-QUIC-RFC9002-S6P4-0004` Discard secrets as soon as the replacement keys exist

## Risks And Follow-Up Notes
- The new helper surface covers the RFC 9002 math and timing clauses that can be proven without a sender/recovery state machine.
- Retry, PTO-emission, and key-discard cleanup clauses remain blocked by missing send-path and recovery-state plumbing.
- The repository still has unrelated pre-existing worktree changes; this summary only reflects the files touched for this chunk.
