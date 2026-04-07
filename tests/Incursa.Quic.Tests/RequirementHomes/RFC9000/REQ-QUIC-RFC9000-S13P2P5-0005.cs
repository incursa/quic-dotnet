namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P2P5-0005")]
public sealed class REQ_QUIC_RFC9000_S13P2P5_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P1-0014")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0010")]
    [Requirement("REQ-QUIC-RFC9002-S3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_UsesEcnCountsAndReportsMeasuredDelayWhenDelayed()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1000,
            congestionExperienced: true,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 4000, out QuicAckFrame frame));

        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.Equal(3000UL, frame.AckDelay);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(11UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(12UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(13UL, frame.EcnCounts!.Value.EcnCeCount);
        Assert.True(frame.AckDelay > 1000UL);
    }
}
