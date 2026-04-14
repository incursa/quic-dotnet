namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0038">A sender can discard this information after a period of time elapses that adequately allows for reordering, such as a PTO (Section 6.2 of [QUIC-RECOVERY]), or based on other events, such as reaching a memory limit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0038")]
public sealed class REQ_QUIC_RFC9000_S13P3_0038
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPendingRetransmissionsOlderThan_RemovesQueuedRetransmissionsPastTheCutoff()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 900,
            SentAtMicros: 200,
            AckEliciting: true));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            8,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(2, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPendingRetransmissionsOlderThan(150));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(8UL, retransmission.PacketNumber);
        Assert.Equal(200UL, retransmission.SentAtMicros);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPendingRetransmissionsOlderThan_LeavesQueuedRetransmissionsAtOrAfterTheCutoff()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 900,
            SentAtMicros: 200,
            AckEliciting: true));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            8,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
        Assert.Equal(2, runtime.PendingRetransmissionCount);

        Assert.False(runtime.TryDiscardPendingRetransmissionsOlderThan(100));

        Assert.Equal(2, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan firstRetransmission));
        Assert.Equal(7UL, firstRetransmission.PacketNumber);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan secondRetransmission));
        Assert.Equal(8UL, secondRetransmission.PacketNumber);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDiscardPendingRetransmissionsOlderThan_ClearsTheLossDetectionDeadlineWhenTheQueueWasTheLastRetainedState()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 150,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));
        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.NotNull(runtime.LossDetectionDeadlineMicros);
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPendingRetransmissionsOlderThan(200));

        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }
}
