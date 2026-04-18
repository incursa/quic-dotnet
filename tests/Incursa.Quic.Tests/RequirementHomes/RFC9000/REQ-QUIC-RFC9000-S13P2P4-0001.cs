namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P4-0001">In cases with ACK frame loss and reordering, this approach does not guarantee that every acknowledgment is seen by the sender before it is no longer included in the ACK frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
public sealed class REQ_QUIC_RFC9000_S13P2P4_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_PreservesTheTrackedAckRangesBeforeNewerPacketsArrive()
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges: 2);
        RecordAckedRanges(tracker);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(6UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(1UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(2UL, frame.AdditionalRanges[0].LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DropsTheOldestAckRangeAfterTheWindowAdvances()
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges: 2);
        RecordAckedRanges(tracker);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            9,
            ackEliciting: true,
            receivedAtMicros: 1_060);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            10,
            ackEliciting: true,
            receivedAtMicros: 1_070);

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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_WithASingleRangeLimitKeepsOnlyTheNewestAckRange()
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges: 1);
        RecordAckedRanges(tracker);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(6UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    private static void RecordAckedRanges(QuicAckGenerationState tracker)
    {
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1_010);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 5, ackEliciting: true, receivedAtMicros: 1_020);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 6, ackEliciting: true, receivedAtMicros: 1_030);
    }
}
