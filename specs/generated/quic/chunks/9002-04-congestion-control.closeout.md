# 9002-04-congestion-control Closeout

## Verdict
`trace-consistent-with-implemented-and-deferred-items`

## Scope
- RFC: `9002`
- Section tokens: `S7`, `S7P1`, `S7P2`, `S7P3P1`, `S7P3P2`, `S7P3P3`, `S7P4`, `S7P5`, `S7P6`, `S7P6P1`, `S7P6P2`, `S7P7`, `S7P8`
- Spec file: `./specs/requirements/quic/SPEC-QUIC-RFC9002.json`

## Coverage Summary
- Total in scope: 46
- Implemented and tested: 39
- Deferred: 7
- Blocked: 0
- Uncovered: 0

## Trace Check
- Test requirement refs found: 46 scoped IDs, all within the selected section tokens.
- Source requirement refs found: none
- XML-comment requirement refs found: none
- Stale or wrong requirement IDs found: none
- Silent gaps found: none

## In-Scope Requirements
### S7
- `REQ-QUIC-RFC9002-S7-0001` - Require alternate controllers to obey RFC 8085. Status: deferred. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers. Gap: No alternate-controller or RFC 8085 send-policy surface exists yet.
- `REQ-QUIC-RFC9002-S7-0002` - Exclude ACK-only packets from bytes in flight. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: CanSendAndRegisterPacketSent_TreatAckOnlyPacketsAsFreeButCountProbesAsFlight.
- `REQ-QUIC-RFC9002-S7-0003` - Exclude ACK-only packets from congestion control. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: CanSendAndRegisterPacketSent_TreatAckOnlyPacketsAsFreeButCountProbesAsFlight.
- `REQ-QUIC-RFC9002-S7-0004` - Allow ACK-only loss signals to influence control. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: CanSendAndRegisterPacketSent_TreatAckOnlyPacketsAsFreeButCountProbesAsFlight, TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7-0005` - Keep congestion control per path. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: Constructor_SeedsTheControllerWithTheInitialWindowAndKeepsInstancesIndependent.
- `REQ-QUIC-RFC9002-S7-0006` - Respect the bytes-in-flight ceiling. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: CanSendAndRegisterPacketSent_TreatAckOnlyPacketsAsFreeButCountProbesAsFlight.

### S7P1
- `REQ-QUIC-RFC9002-S7P1-0001` - Treat ECN CE as congestion on validated paths. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.

### S7P2
- `REQ-QUIC-RFC9002-S7P2-0001` - Start each connection in slow start. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: Constructor_SeedsTheControllerWithTheInitialWindowAndKeepsInstancesIndependent.
- `REQ-QUIC-RFC9002-S7P2-0002` - Recommend the initial congestion window. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: ComputeInitialCongestionWindowBytes_HonorsTheTransitionPoints, ComputeInitialCongestionWindowBytes_RejectsZeroDatagramSizes.
- `REQ-QUIC-RFC9002-S7P2-0003` - Recompute the initial window when datagram size changes. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: Constructor_SeedsTheControllerWithTheInitialWindowAndKeepsInstancesIndependent, ComputeInitialWindowAndResetToInitialWindow_FollowTheDatagramSize.
- `REQ-QUIC-RFC9002-S7P2-0004` - Reset the initial window after handshake-driven MTU reduction. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: Constructor_SeedsTheControllerWithTheInitialWindowAndKeepsInstancesIndependent, ComputeInitialWindowAndResetToInitialWindow_FollowTheDatagramSize.
- `REQ-QUIC-RFC9002-S7P2-0005` - Recommend a two-packet minimum congestion window. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: Constructor_SeedsTheControllerWithTheInitialWindowAndKeepsInstancesIndependent.

### S7P3P1
- `REQ-QUIC-RFC9002-S7P3P1-0001` - Enter recovery on loss or ECN-CE increase. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P1-0002` - Enter slow start when the window is below threshold. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P1-0003` - Increase cwnd by acknowledged bytes in slow start. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.

### S7P3P2
- `REQ-QUIC-RFC9002-S7P3P2-0001` - Stay in recovery once entered. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P2-0002` - Do not reenter recovery while already there. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P2-0003` - Cut the slow start threshold on recovery entry. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P2-0004` - Restore congestion window before leaving recovery. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P2-0005` - Permit gentler recovery-window reduction. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P2-0006` - Hold the congestion window steady during recovery. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P2-0007` - Leave recovery when a recovery-period packet is acknowledged. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.

### S7P3P3
- `REQ-QUIC-RFC9002-S7P3P3-0001` - Remain in congestion avoidance only while the window is above the threshold. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P3P3-0002` - Limit congestion-avoidance growth to one datagram per acknowledged window. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.

### S7P4
- `REQ-QUIC-RFC9002-S7P4-0001` - Ignore undecryptable packet loss before keys are available. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.
- `REQ-QUIC-RFC9002-S7P4-0002` - Do not ignore later packet loss. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryRegisterLossAndProcessEcn_EnterRecoveryOnlyForEligibleSignals.

### S7P5
- `REQ-QUIC-RFC9002-S7P5-0001` - Do not block probe packets with congestion control. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: CanSendAndRegisterPacketSent_TreatAckOnlyPacketsAsFreeButCountProbesAsFlight.
- `REQ-QUIC-RFC9002-S7P5-0002` - Count probe packets as additional flight. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: CanSendAndRegisterPacketSent_TreatAckOnlyPacketsAsFreeButCountProbesAsFlight.

### S7P6
- `REQ-QUIC-RFC9002-S7P6-0001` - Declare persistent congestion when all long-duration packets are lost. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_RequiresAckElicitingLossesAcrossTheWindow.

### S7P6P1
- `REQ-QUIC-RFC9002-S7P6P1-0001` - Compute persistent congestion duration from RTT and max_ack_delay. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_RequiresAckElicitingLossesAcrossTheWindow.
- `REQ-QUIC-RFC9002-S7P6P1-0002` - Include max_ack_delay in persistent congestion duration. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_RequiresAckElicitingLossesAcrossTheWindow.
- `REQ-QUIC-RFC9002-S7P6P1-0003` - Recommend a persistent congestion threshold of three. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_RequiresAckElicitingLossesAcrossTheWindow.

### S7P6P2
- `REQ-QUIC-RFC9002-S7P6P2-0001` - Establish persistent congestion after the full loss test passes. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_RequiresAckElicitingLossesAcrossTheWindow.
- `REQ-QUIC-RFC9002-S7P6P2-0002` - Require the two declared-lost packets to be ack-eliciting. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_DetectsPersistentCongestionWhenBothDeclaredLostPacketsAreAckEliciting.
- `REQ-QUIC-RFC9002-S7P6P2-0003` - Delay persistent congestion until at least one RTT sample exists. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_DelaysDetectionUntilAnRttSampleExists, TryDetectPersistentCongestion_StartsOnceAnRttSampleIsAvailable, TryDetectPersistentCongestion_DoesNotStartBeforeAnyRttSampleExists.
- `REQ-QUIC-RFC9002-S7P6P2-0004` - Consider packet number spaces when declaring persistent congestion. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_ConsidersPacketsAcrossPacketNumberSpaces.
- `REQ-QUIC-RFC9002-S7P6P2-0005` - Allow limited packet-number-space state when necessary. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_DoesNotNeedCrossSpaceStateToRejectTooShortSingleSpaceWindows, TryDetectPersistentCongestion_StillDetectsPersistentCongestionWhenOnlyApplicationDataStateIsTrackedAtTheBoundary.
- `REQ-QUIC-RFC9002-S7P6P2-0006` - Reset cwnd to the minimum on persistent congestion. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryDetectPersistentCongestion_CollapsesTheWindowWhenPersistentCongestionIsDetected, TryDetectPersistentCongestion_DoesNotCollapseTheWindowWhenTheDurationIsTooShort, TryDetectPersistentCongestion_CollapsesTheWindowAtTheDurationBoundary.

### S7P7
- `REQ-QUIC-RFC9002-S7P7-0001` - Pace all in-flight packets. Status: deferred. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers. Gap: The repo still lacks a real packet scheduler/send loop that can pace every in-flight packet.
- `REQ-QUIC-RFC9002-S7P7-0002` - Either pace or cap bursts. Status: deferred. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers. Gap: Burst capping versus pacing is only modeled as helper math; enforcement belongs in sender orchestration.
- `REQ-QUIC-RFC9002-S7P7-0003` - Limit bursts to the initial congestion window. Status: deferred. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers. Gap: Initial-window burst capping is not yet wired to a concrete transmit queue.
- `REQ-QUIC-RFC9002-S7P7-0004` - Allow larger bursts when the path can absorb them. Status: deferred. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers. Gap: Larger-burst allowance needs path-level scheduling decisions that are outside the current helper slice.
- `REQ-QUIC-RFC9002-S7P7-0005` - Do not pace pure ACK packets. Status: deferred. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers. Gap: The helper can skip pacing pure ACKs, but the sender layer that decides which packets are ACK-only is still missing.

### S7P8
- `REQ-QUIC-RFC9002-S7P8-0001` - Do not increase cwnd when underutilized. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers.
- `REQ-QUIC-RFC9002-S7P8-0002` - Do not call yourself application-limited because of pacing delay. Status: deferred. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers. Gap: Application-limited classification due to pacing delay is a sender-state concern that is not represented yet.
- `REQ-QUIC-RFC9002-S7P8-0003` - Allow alternate cwnd-updating mechanisms after underutilization. Status: implemented and tested. Evidence: src/Incursa.Quic/QuicCongestionControlState.cs, src/Incursa.Quic/PublicAPI.Unshipped.txt; tests: TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers.

## Deferred Requirements
- `REQ-QUIC-RFC9002-S7-0001` - No alternate-controller or RFC 8085 send-policy surface exists yet.
- `REQ-QUIC-RFC9002-S7P7-0001` - The repo still lacks a real packet scheduler/send loop that can pace every in-flight packet.
- `REQ-QUIC-RFC9002-S7P7-0002` - Burst capping versus pacing is only modeled as helper math; enforcement belongs in sender orchestration.
- `REQ-QUIC-RFC9002-S7P7-0003` - Initial-window burst capping is not yet wired to a concrete transmit queue.
- `REQ-QUIC-RFC9002-S7P7-0004` - Larger-burst allowance needs path-level scheduling decisions that are outside the current helper slice.
- `REQ-QUIC-RFC9002-S7P7-0005` - The helper can skip pacing pure ACKs, but the sender layer that decides which packets are ACK-only is still missing.
- `REQ-QUIC-RFC9002-S7P8-0002` - Application-limited classification due to pacing delay is a sender-state concern that is not represented yet.

## Verification
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicCongestionControlStateTests"` - `6/6 passed`
- `dotnet build benchmarks/Incursa.Quic.Benchmarks.csproj` - `Succeeded`
- `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj` - `326/326 passed`

## Notes
- No reconciliation artifact existed for this chunk; the implementation summary was treated as the source of truth.
- The helper slice intentionally defers the full sender/pacer behavior for RFC 9002 Section 7.7 and the pacing-delay portion of Section 7.8.
