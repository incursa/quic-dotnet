# 9002-03-loss-detection Closeout

## Verdict
`clean_with_explicit_blockers`

## Scope
- RFC: `9002`
- Section tokens: `S6`, `S6P1`, `S6P1P1`, `S6P1P2`, `S6P2`, `S6P2P1`, `S6P2P2`, `S6P2P2P1`, `S6P2P3`, `S6P2P4`, `S6P3`, `S6P4`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`

## In-Scope Requirements
### S6
- `REQ-QUIC-RFC9002-S6-0001` - Separate loss detection by packet number space. Status: blocked. Gap: Needs packet-number-space-specific loss-state tracking to prove isolation beyond helper-level timing formulas.

### S6P1
- `REQ-QUIC-RFC9002-S6P1-0001` - Declare loss only for packets that satisfy the basic loss criteria. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::CanDeclarePacketLost_RequiresAnUnacknowledgedInFlightPacketSentBeforeAnAcknowledgedPacket`.
- `REQ-QUIC-RFC9002-S6P1-0002` - Allow smaller initial reordering thresholds with adaptation. Status: blocked. Gap: Needs an adaptive reordering-threshold policy; the current slice only exposes static loss timing math.

### S6P1P1
- `REQ-QUIC-RFC9002-S6P1P1-0001` - Recommend a packet threshold of three. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::ShouldDeclarePacketLostByPacketThreshold_UsesTheRecommendedThresholdOfThree`.
- `REQ-QUIC-RFC9002-S6P1P1-0002` - Avoid packet thresholds below three. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::ShouldDeclarePacketLostByPacketThreshold_UsesTheRecommendedThresholdOfThree`, `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::ShouldDeclarePacketLostByPacketThreshold_RejectsThresholdsBelowThree`.

### S6P1P2
- `REQ-QUIC-RFC9002-S6P1P2-0001` - Declare earlier packets lost after sufficient time. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryComputeRemainingLossDelayMicros_SchedulesTheRemainingTimeBeforeLoss`.
- `REQ-QUIC-RFC9002-S6P1P2-0002` - Bound the time threshold by timer granularity. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::ComputeLossDelayMicros_UsesTheRttAndGranularityThresholds`.
- `REQ-QUIC-RFC9002-S6P1P2-0003` - Compute the time threshold from RTT and granularity. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::ComputeLossDelayMicros_UsesTheRttAndGranularityThresholds`.
- `REQ-QUIC-RFC9002-S6P1P2-0004` - Schedule a timer for the remaining time before declaring loss. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryComputeRemainingLossDelayMicros_SchedulesTheRemainingTimeBeforeLoss`.
- `REQ-QUIC-RFC9002-S6P1P2-0005` - Use the recommended packet-threshold multiplier. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::ComputeLossDelayMicros_UsesTheRttAndGranularityThresholds`.
- `REQ-QUIC-RFC9002-S6P1P2-0006` - Use a one-millisecond timer granularity. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::ComputeLossDelayMicros_UsesTheRttAndGranularityThresholds`.
- `REQ-QUIC-RFC9002-S6P1P2-0007` - Allow alternative time-threshold experiments. Status: blocked. Gap: Needs sender/recovery state that is not present in the helper-only slice.

### S6P2
- `REQ-QUIC-RFC9002-S6P2-0001` - Send probe datagrams on PTO expiration or address-validation uncertainty. Status: blocked. Gap: Needs a sender/transmit surface that can emit probe datagrams and apply address-validation gating.
- `REQ-QUIC-RFC9002-S6P2-0002` - Compute PTO per packet number space. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryComputeProbeTimeoutMicros_UsesThePerSpaceFormula`.
- `REQ-QUIC-RFC9002-S6P2-0003` - Do not infer loss from PTO expiration. Status: blocked. Gap: Needs sender-side loss-recovery orchestration to prove PTO expiration does not itself mark packets lost.

### S6P2P1
- `REQ-QUIC-RFC9002-S6P2P1-0001` - Schedule PTO after ack-eliciting transmission. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryComputeProbeTimeoutMicros_UsesThePerSpaceFormula`.
- `REQ-QUIC-RFC9002-S6P2P1-0002` - Set max_ack_delay to zero for early handshake spaces. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryComputeProbeTimeoutMicros_UsesThePerSpaceFormula`.
- `REQ-QUIC-RFC9002-S6P2P1-0003` - Keep PTO above granularity. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryComputeProbeTimeoutMicros_UsesThePerSpaceFormula`.
- `REQ-QUIC-RFC9002-S6P2P1-0004` - Use the earlier PTO across Initial and Handshake spaces. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TrySelectInitialOrHandshakeProbeTimeoutMicros_UsesTheEarlierValue`.
- `REQ-QUIC-RFC9002-S6P2P1-0005` - Defer application-data PTO until handshake confirmation. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryComputeProbeTimeoutMicros_UsesThePerSpaceFormula`, `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryComputeProbeTimeoutMicros_RejectsApplicationDataBeforeHandshakeConfirmation`.
- `REQ-QUIC-RFC9002-S6P2P1-0006` - Restart PTO on send, acknowledgment, or key discard. Status: blocked. Gap: Needs sender/recovery state transitions to restart PTO after sends, acknowledgments, or key discard.
- `REQ-QUIC-RFC9002-S6P2P1-0007` - Increase PTO backoff on timeout. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::ComputeProbeTimeoutWithBackoffMicros_DoublesTheBasePtoOnTimeout`.
- `REQ-QUIC-RFC9002-S6P2P1-0008` - Reset PTO backoff on acknowledgment. Status: blocked. Gap: Needs sender/recovery state transitions to reset PTO backoff on acknowledgment.
- `REQ-QUIC-RFC9002-S6P2P1-0009` - Suppress PTO-backoff reset on unvalidated Initial acknowledgments. Status: blocked. Gap: Needs handshake- and validation-aware ack-processing state to suppress Initial backoff resets correctly.
- `REQ-QUIC-RFC9002-S6P2P1-0010` - Avoid conflicting timers. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TrySelectRecoveryTimerMicros_PrefersLossDetectionTimersOverPtoTimers`.

### S6P2P2
- `REQ-QUIC-RFC9002-S6P2P2-0001` - Reuse prior-smoothed RTT on resumed connections. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRttEstimator.cs`; tests: `tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs::ConstructorAndReset_SeedTheEstimatorWithTheInitialRtt`.
- `REQ-QUIC-RFC9002-S6P2P2-0002` - Default initial RTT to 333 milliseconds. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRttEstimator.cs`; tests: `tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs::ConstructorAndReset_SeedTheEstimatorWithTheInitialRtt`.
- `REQ-QUIC-RFC9002-S6P2P2-0003` - Use PATH_CHALLENGE and PATH_RESPONSE timing for initial RTT. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicPathValidation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicPathValidationTests.cs::TryMeasurePathChallengeRoundTripMicros_ComputesTheElapsedTimeWithoutUpdatingRttState`.
- `REQ-QUIC-RFC9002-S6P2P2-0004` - Do not treat PATH_CHALLENGE/PATH_RESPONSE delay as an RTT sample. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicPathValidation.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicPathValidationTests.cs::TryMeasurePathChallengeRoundTripMicros_ComputesTheElapsedTimeWithoutUpdatingRttState`.
- `REQ-QUIC-RFC9002-S6P2P2-0005` - Reset timers when keys are discarded. Status: blocked. Gap: Needs key-discard plumbing that resets the PTO and loss-detection timers.

### S6P2P2P1
- `REQ-QUIC-RFC9002-S6P2P2P1-0001` - Delay server PTO until address validation traffic arrives. Status: blocked. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0002` - Reset the server PTO when the client sends data. Status: blocked. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0003` - Fire a past-due PTO immediately. Status: blocked. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0004` - Arm the client PTO before handshake confirmation. Status: blocked. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0005` - Send Handshake probes when keys are available. Status: blocked. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0006` - Send Initial probes otherwise. Status: blocked. Gap: Needs client/server PTO-arming logic and address-validation state.

### S6P2P3
- `REQ-QUIC-RFC9002-S6P2P3-0001` - Permit early CRYPTO probes for handshake speedup. Status: blocked. Gap: Needs handshake-speedup probe policy and CRYPTO send-path integration.

### S6P2P4
- `REQ-QUIC-RFC9002-S6P2P4-0001` - Probe with at least one ack-eliciting packet. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0002` - Allow two full-sized PTO datagrams. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0003` - Keep PTO probe packets ack-eliciting. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0004` - Use other packet number spaces for PTO probes. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0005` - Include new data in PTO probes. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0006` - Allow previously sent data in PTO probes. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0007` - Allow alternative probe-content strategies. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0008` - Send a PING when no probe data exists. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0009` - Allow declaring in-flight packets lost instead of probing. Status: blocked. Gap: Needs PTO probe packet composition and send-path packet selection logic.

### S6P3
- `REQ-QUIC-RFC9002-S6P3-0001` - Reject Retry as an acknowledgment. Status: blocked. Gap: Needs Retry packet classification in the connection-establishment state machine.
- `REQ-QUIC-RFC9002-S6P3-0002` - Reset recovery and congestion state on Retry. Status: blocked. Gap: Needs client recovery-state reset plumbing for Retry processing.
- `REQ-QUIC-RFC9002-S6P3-0003` - Retain cryptographic handshake state across Retry. Status: blocked. Gap: Needs Retry-aware connection state that preserves handshake messages while resetting recovery state.
- `REQ-QUIC-RFC9002-S6P3-0004` - Permit RTT estimation from Retry timing. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryMeasureRetryRoundTripMicros_ComputesTheElapsedTimeAndCanSeedInitialRtt`.
- `REQ-QUIC-RFC9002-S6P3-0005` - Allow using Retry-derived RTT as the initial RTT. Status: implemented and tested. Evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/PublicAPI.Unshipped.txt`; tests: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs::TryMeasureRetryRoundTripMicros_ComputesTheElapsedTimeAndCanSeedInitialRtt`.

### S6P4
- `REQ-QUIC-RFC9002-S6P4-0001` - Discard recovery state when protection keys go away. Status: blocked. Gap: Needs key-discard recovery cleanup and bytes-in-flight integration.
- `REQ-QUIC-RFC9002-S6P4-0002` - Remove discarded packets from bytes in flight. Status: blocked. Gap: Needs key-discard recovery cleanup and bytes-in-flight integration.
- `REQ-QUIC-RFC9002-S6P4-0003` - Discard recovery state for rejected 0-RTT packets. Status: blocked. Gap: Needs key-discard recovery cleanup and bytes-in-flight integration.
- `REQ-QUIC-RFC9002-S6P4-0004` - Discard secrets as soon as the replacement keys exist. Status: blocked. Gap: Needs key-discard recovery cleanup and bytes-in-flight integration.

## Coverage Summary
- Total in scope: 55
- Implemented and tested: 23
- Blocked: 32
- Deferred: 0
- Uncovered: 0

## Trace Check
- Test requirement refs found: 23 scoped IDs, all within the selected section tokens.
- Source requirement refs found: none.
- XML-comment requirement refs found: none.
- Stale or wrong requirement IDs found: none.
- Silent gaps found: none.

## Remaining Open Requirements
### S6
- `REQ-QUIC-RFC9002-S6-0001` - Separate loss detection by packet number space. Gap: Needs packet-number-space-specific loss-state tracking to prove isolation beyond helper-level timing formulas.

### S6P1
- `REQ-QUIC-RFC9002-S6P1-0002` - Allow smaller initial reordering thresholds with adaptation. Gap: Needs an adaptive reordering-threshold policy; the current slice only exposes static loss timing math.

### S6P1P1
- none

### S6P1P2
- `REQ-QUIC-RFC9002-S6P1P2-0007` - Allow alternative time-threshold experiments. Gap: Needs sender/recovery state that is not present in the helper-only slice.

### S6P2
- `REQ-QUIC-RFC9002-S6P2-0001` - Send probe datagrams on PTO expiration or address-validation uncertainty. Gap: Needs a sender/transmit surface that can emit probe datagrams and apply address-validation gating.
- `REQ-QUIC-RFC9002-S6P2-0003` - Do not infer loss from PTO expiration. Gap: Needs sender-side loss-recovery orchestration to prove PTO expiration does not itself mark packets lost.

### S6P2P1
- `REQ-QUIC-RFC9002-S6P2P1-0006` - Restart PTO on send, acknowledgment, or key discard. Gap: Needs sender/recovery state transitions to restart PTO after sends, acknowledgments, or key discard.
- `REQ-QUIC-RFC9002-S6P2P1-0008` - Reset PTO backoff on acknowledgment. Gap: Needs sender/recovery state transitions to reset PTO backoff on acknowledgment.
- `REQ-QUIC-RFC9002-S6P2P1-0009` - Suppress PTO-backoff reset on unvalidated Initial acknowledgments. Gap: Needs handshake- and validation-aware ack-processing state to suppress Initial backoff resets correctly.

### S6P2P2
- `REQ-QUIC-RFC9002-S6P2P2-0005` - Reset timers when keys are discarded. Gap: Needs key-discard plumbing that resets the PTO and loss-detection timers.

### S6P2P2P1
- `REQ-QUIC-RFC9002-S6P2P2P1-0001` - Delay server PTO until address validation traffic arrives. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0002` - Reset the server PTO when the client sends data. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0003` - Fire a past-due PTO immediately. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0004` - Arm the client PTO before handshake confirmation. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0005` - Send Handshake probes when keys are available. Gap: Needs client/server PTO-arming logic and address-validation state.
- `REQ-QUIC-RFC9002-S6P2P2P1-0006` - Send Initial probes otherwise. Gap: Needs client/server PTO-arming logic and address-validation state.

### S6P2P3
- `REQ-QUIC-RFC9002-S6P2P3-0001` - Permit early CRYPTO probes for handshake speedup. Gap: Needs handshake-speedup probe policy and CRYPTO send-path integration.

### S6P2P4
- `REQ-QUIC-RFC9002-S6P2P4-0001` - Probe with at least one ack-eliciting packet. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0002` - Allow two full-sized PTO datagrams. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0003` - Keep PTO probe packets ack-eliciting. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0004` - Use other packet number spaces for PTO probes. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0005` - Include new data in PTO probes. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0006` - Allow previously sent data in PTO probes. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0007` - Allow alternative probe-content strategies. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0008` - Send a PING when no probe data exists. Gap: Needs PTO probe packet composition and send-path packet selection logic.
- `REQ-QUIC-RFC9002-S6P2P4-0009` - Allow declaring in-flight packets lost instead of probing. Gap: Needs PTO probe packet composition and send-path packet selection logic.

### S6P3
- `REQ-QUIC-RFC9002-S6P3-0001` - Reject Retry as an acknowledgment. Gap: Needs Retry packet classification in the connection-establishment state machine.
- `REQ-QUIC-RFC9002-S6P3-0002` - Reset recovery and congestion state on Retry. Gap: Needs client recovery-state reset plumbing for Retry processing.
- `REQ-QUIC-RFC9002-S6P3-0003` - Retain cryptographic handshake state across Retry. Gap: Needs Retry-aware connection state that preserves handshake messages while resetting recovery state.

### S6P4
- `REQ-QUIC-RFC9002-S6P4-0001` - Discard recovery state when protection keys go away. Gap: Needs key-discard recovery cleanup and bytes-in-flight integration.
- `REQ-QUIC-RFC9002-S6P4-0002` - Remove discarded packets from bytes in flight. Gap: Needs key-discard recovery cleanup and bytes-in-flight integration.
- `REQ-QUIC-RFC9002-S6P4-0003` - Discard recovery state for rejected 0-RTT packets. Gap: Needs key-discard recovery cleanup and bytes-in-flight integration.
- `REQ-QUIC-RFC9002-S6P4-0004` - Discard secrets as soon as the replacement keys exist. Gap: Needs key-discard recovery cleanup and bytes-in-flight integration.

## Verification
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicRecoveryTimingTests|FullyQualifiedName~QuicPathValidationTests|FullyQualifiedName~QuicRttEstimatorTests"` - `36 passed, 0 failed, 0 skipped`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj` - `294 passed, 0 failed, 0 skipped`

## Notes
- No reconciliation artifact existed for this chunk; the implementation summary was the source of truth.
- Scoped direct refs were added only in tests; the source helpers stay convention-consistent for this slice.
