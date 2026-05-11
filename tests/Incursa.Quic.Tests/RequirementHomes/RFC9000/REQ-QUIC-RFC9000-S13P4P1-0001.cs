namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P1-0001")]
public sealed class REQ_QUIC_RFC9000_S13P4P1_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_DoesNotReportEcnCountsWithoutRecordedEcnFields()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1000);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 4000,
            out QuicAckFrame frame));
        Assert.Equal((byte)0x02, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.Null(frame.EcnCounts);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_ReportsEcnCountsWhenRecordedEcnFieldsAreAvailable()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1000,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 4000,
            out QuicAckFrame frame));
        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(11UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(12UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(13UL, frame.EcnCounts!.Value.EcnCeCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_StillOmitsEcnCountsWhenCongestionWasExperiencedWithoutEcnFields()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            9,
            ackEliciting: true,
            receivedAtMicros: 1000,
            congestionExperienced: true);

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 4000,
            out QuicAckFrame frame));
        Assert.Equal((byte)0x02, frame.FrameType);
        Assert.Equal(9UL, frame.LargestAcknowledged);
        Assert.Null(frame.EcnCounts);
    }
}
