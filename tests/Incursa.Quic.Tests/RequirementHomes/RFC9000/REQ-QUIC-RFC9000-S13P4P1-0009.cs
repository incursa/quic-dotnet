namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P1-0009")]
public sealed class REQ_QUIC_RFC9000_S13P4P1_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordIncomingPacket_ReportsEcnCountsWhenAProcessedPacketCarriesThem()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 4_000,
            out QuicAckFrame frame));
        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(11UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(12UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(13UL, frame.EcnCounts!.Value.EcnCeCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordIncomingPacket_DoesNotReportEcnCountsWhenAProcessedPacketHasNoEcnObservation()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 4_000,
            out QuicAckFrame frame));
        Assert.Equal((byte)0x02, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.Null(frame.EcnCounts);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0009")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordIncomingPacket_ReportsEcnCountsForProcessedNonAckElicitingPacket()
    {
        QuicSenderFlowController sender = new();

        // ECN accounting follows packet processing, not ACK elicitation.
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            9,
            ackEliciting: false,
            receivedAtMicros: 1_000,
            ecnCounts: new QuicEcnCounts(3, 4, 5));

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 4_000,
            out QuicAckFrame frame));
        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(9UL, frame.LargestAcknowledged);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(3UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(4UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(5UL, frame.EcnCounts!.Value.EcnCeCount);
    }
}
