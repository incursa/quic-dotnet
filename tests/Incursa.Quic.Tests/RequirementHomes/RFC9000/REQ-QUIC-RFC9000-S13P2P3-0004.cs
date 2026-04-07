namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P2P3-0004")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_TrimsOldestRangesWhenLimitReached()
    {
        QuicAckGenerationState keepTwoRanges = new(maximumRetainedAckRanges: 2);
        RecordAckedRanges(keepTwoRanges);

        Assert.True(keepTwoRanges.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 2000, out QuicAckFrame frame));
        Assert.Equal(10UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(5UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(6UL, frame.AdditionalRanges[0].LargestAcknowledged);

        QuicAckGenerationState keepOnlyLargestRange = new(maximumRetainedAckRanges: 1);
        RecordAckedRanges(keepOnlyLargestRange);

        Assert.True(keepOnlyLargestRange.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 2000, out QuicAckFrame compactFrame));
        Assert.Equal(10UL, compactFrame.LargestAcknowledged);
        Assert.Equal(1UL, compactFrame.FirstAckRange);
        Assert.Empty(compactFrame.AdditionalRanges);
    }

    private static void RecordAckedRanges(QuicAckGenerationState tracker)
    {
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1010);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 5, ackEliciting: true, receivedAtMicros: 1020);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 6, ackEliciting: true, receivedAtMicros: 1030);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 9, ackEliciting: true, receivedAtMicros: 1040);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 10, ackEliciting: true, receivedAtMicros: 1050);
    }
}
