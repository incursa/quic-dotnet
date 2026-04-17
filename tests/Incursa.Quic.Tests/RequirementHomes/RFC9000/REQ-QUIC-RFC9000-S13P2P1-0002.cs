namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0002">Every packet SHOULD be acknowledged at least once.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0002")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_IncludesContiguousAckElicitingAndNonAckElicitingPackets()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: false,
            receivedAtMicros: 1_010);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(2UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_ReturnsFalseWithoutTrackedPackets()
    {
        QuicAckGenerationState tracker = new();

        Assert.False(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_PreservesSparsePacketRanges()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            ackEliciting: false,
            receivedAtMicros: 1_010);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 5,
            ackEliciting: true,
            receivedAtMicros: 1_020);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(5UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Equal(2UL, frame.AckRangeCount);
        Assert.Equal(3UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(3UL, frame.AdditionalRanges[0].LargestAcknowledged);
        Assert.Equal(1UL, frame.AdditionalRanges[1].SmallestAcknowledged);
        Assert.Equal(1UL, frame.AdditionalRanges[1].LargestAcknowledged);
    }
}
