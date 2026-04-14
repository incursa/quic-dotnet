namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0034">Endpoints SHOULD prioritize retransmission of data over sending new data, unless priorities specified by the application indicate otherwise.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0034")]
public sealed class REQ_QUIC_RFC9000_S13P3_0034
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_LeavesQueuedRetransmissionsAvailableAfterLaterTrackedPackets()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 900,
            SentAtMicros: 125,
            AckEliciting: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.Single(runtime.SentPackets);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumber == 8);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(7UL, retransmission.PacketNumber);
        Assert.Equal(1_200UL, retransmission.PayloadBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrackSentPacket_DoesNotCreateRetransmissionsWithoutLoss()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 900,
            SentAtMicros: 125,
            AckEliciting: true));

        Assert.Single(runtime.SentPackets);
        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }
}
