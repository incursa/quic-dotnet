namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0005")]
public sealed class REQ_QUIC_INT_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SenderRuntimeTracksLossRetransmissionAndProbeTimeoutState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1200,
            SentAtMicros: 100,
            AckEliciting: true));

        Assert.Single(runtime.SentPackets);
        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 250,
            smoothedRttMicros: 1000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.True(runtime.LossDetectionDeadlineMicros.HasValue);

        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, 7, handshakeConfirmed: true));
        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan plan));
        Assert.Equal(7UL, plan.PacketNumber);
        Assert.Equal(1200UL, plan.PayloadBytes);
        Assert.Empty(runtime.SentPackets);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AcknowledgedPacketsClearTrackedStateAndResetPtoBackoff()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 256,
            SentAtMicros: 10,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 20,
            smoothedRttMicros: 1000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.ProbeTimeoutCount);

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            9,
            handshakeConfirmed: true));

        Assert.Empty(runtime.SentPackets);
        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
    }
}
