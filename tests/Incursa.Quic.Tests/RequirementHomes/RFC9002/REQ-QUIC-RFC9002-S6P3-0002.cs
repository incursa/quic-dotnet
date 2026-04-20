namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P3-0002">Clients that receive a Retry packet MUST reset congestion control and loss recovery state, including any pending timers.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P3-0002")]
public sealed class REQ_QUIC_RFC9002_S6P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResetProbeTimeoutBackoffCount_ResetsTheBackoffWhenRetryDiscardsKeys()
    {
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 3,
            initialOrHandshakeKeysDiscarded: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRetryReceivedResetsCongestionControlStateAndPendingTimers()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicCongestionControlState congestionControlState = runtime.SendRuntime.FlowController.CongestionControlState;
        ulong initialCongestionWindowBytes = congestionControlState.CongestionWindowBytes;

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 99,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial)));

        Assert.True(congestionControlState.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 100,
            packetInFlight: true));
        Assert.True(congestionControlState.CongestionWindowBytes < initialCongestionWindowBytes);
        Assert.True(congestionControlState.RecoveryStartTimeMicros.HasValue);

        Assert.True(runtime.SendRuntime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 200,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false));
        Assert.Equal(1, runtime.SendRuntime.ProbeTimeoutCount);
        Assert.NotNull(runtime.SendRuntime.LossDetectionDeadlineMicros);

        QuicConnectionTransitionResult retryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        Assert.True(retryResult.StateChanged);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Keys, key =>
            key.PacketNumberSpace == QuicPacketNumberSpace.Initial
            && key.PacketNumber == 99);
        Assert.Equal(initialCongestionWindowBytes, congestionControlState.CongestionWindowBytes);
        // Retry immediately replays the bootstrap Initial packets, so the post-reset
        // bytes-in-flight count can reflect the fresh ClientHello rather than the discarded packet.
        Assert.False(congestionControlState.RecoveryStartTimeMicros.HasValue);
        Assert.Equal(0, runtime.SendRuntime.ProbeTimeoutCount);
        Assert.Null(runtime.SendRuntime.LossDetectionDeadlineMicros);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery));
        Assert.Contains(retryResult.Effects, effect =>
            effect is QuicConnectionArmTimerEffect armEffect
            && armEffect.TimerKind == QuicConnectionTimerKind.Recovery);
    }
}
