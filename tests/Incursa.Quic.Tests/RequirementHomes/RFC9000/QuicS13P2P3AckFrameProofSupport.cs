namespace Incursa.Quic.Tests;

internal static class QuicS13P2P3AckFrameProofSupport
{
    public static QuicAckGenerationState CreateTrackedState(int maximumRetainedAckRanges)
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges);

        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1_010);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 5, ackEliciting: true, receivedAtMicros: 1_020);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 6, ackEliciting: true, receivedAtMicros: 1_030);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 9, ackEliciting: true, receivedAtMicros: 1_040);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 10, ackEliciting: true, receivedAtMicros: 1_050);

        return tracker;
    }

    public static void AssertBuildsThreeRangeAckFrame(QuicAckGenerationState tracker)
    {
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(10UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Equal(2, frame.AdditionalRanges.Length);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(5UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(6UL, frame.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(1UL, frame.AdditionalRanges[1].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[1].AckRangeLength);
        Assert.Equal(1UL, frame.AdditionalRanges[1].SmallestAcknowledged);
        Assert.Equal(2UL, frame.AdditionalRanges[1].LargestAcknowledged);
    }

    public static void AssertBuildsTrimmedAckFrame(QuicAckGenerationState tracker)
    {
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(10UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(5UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(6UL, frame.AdditionalRanges[0].LargestAcknowledged);
    }

    public static void AssertBuildsSingleRangeAckFrame(QuicAckGenerationState tracker)
    {
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(10UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }
}
