namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP9-0003">When Initial or Handshake keys are discarded, the sender MUST reset `time_of_last_ack_eliciting_packet[pn_space]`, `loss_time[pn_space]`, and `pto_count`, and set the loss detection timer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP9-0003")]
public sealed class REQ_QUIC_RFC9002_SBP9_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossDetectionTimerMicros_PrefersTheResetLossDeadlineOverPto()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: 1_500,
            probeTimeoutMicros: 2_800,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(1_500UL, selectedTimerMicros);
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, true)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectLossDetectionTimerMicros_CancelsPtoWhenRecoveryIsBlocked(
        bool serverAtAntiAmplificationLimit,
        bool noAckElicitingPacketsInFlight,
        bool peerAddressValidationComplete)
    {
        Assert.False(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 2_800,
            serverAtAntiAmplificationLimit: serverAtAntiAmplificationLimit,
            noAckElicitingPacketsInFlight: noAckElicitingPacketsInFlight,
            peerAddressValidationComplete: peerAddressValidationComplete,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectLossDetectionTimerMicros_UsesAnImmediateDeadlineWhenTheResetTimerIsZero()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
            earliestPendingLossTimeMicros: null,
            probeTimeoutMicros: 0,
            serverAtAntiAmplificationLimit: false,
            noAckElicitingPacketsInFlight: false,
            peerAddressValidationComplete: false,
            out ulong selectedTimerMicros));

        Assert.Equal(0UL, selectedTimerMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP11-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeTlsInitialKeyDiscardResetsSendTimerStateAndClearsDiscardedSpace()
    {
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            PacketProtectionLevel: QuicTlsEncryptionLevel.Initial));
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt));
        Assert.True(runtime.SendRuntime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 300,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false));
        Assert.Equal(1, runtime.SendRuntime.ProbeTimeoutCount);
        Assert.NotNull(runtime.SendRuntime.LossDetectionDeadlineMicros);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysDiscarded,
                    QuicTlsEncryptionLevel.Initial)),
            nowTicks: 4);

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.Equal(0, runtime.SendRuntime.ProbeTimeoutCount);
        Assert.Null(runtime.SendRuntime.LossDetectionDeadlineMicros);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Contains(runtime.SendRuntime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP11-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDiscardPacketNumberSpace_ResetsRecoveryControllerLossAndPtoState()
    {
        QuicRecoveryController controller = new();
        controller.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
            packetNumber: 1,
            sentAtMicros: 100,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.Initial);
        controller.RecordProbeTimeoutExpired();
        Assert.Equal(1, controller.ProbeTimeoutBackoffCount);
        Assert.True(controller.TrySelectLossDetectionTimer(
            nowMicros: 200,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: false,
            handshakeKeysAvailable: true,
            out ulong selectedRecoveryTimerMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, selectedPacketNumberSpace);
        Assert.NotEqual(0UL, selectedRecoveryTimerMicros);

        Assert.True(controller.TryDiscardPacketNumberSpace(
            QuicPacketNumberSpace.Initial,
            resetProbeTimeoutBackoff: true));

        Assert.Equal(0, controller.ProbeTimeoutBackoffCount);
        Assert.False(controller.TrySelectLossDetectionTimer(
            nowMicros: 300,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false,
            serverAtAntiAmplificationLimit: false,
            peerAddressValidationComplete: false,
            handshakeKeysAvailable: true,
            out _,
            out _));
    }
}
