namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P3-0002">ACK frames SHOULD always acknowledge the most recently received packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
public sealed class REQ_QUIC_RFC9000_S13P2P3_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_AcknowledgesTheMostRecentlyReceivedPackets()
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges: 2);

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: true,
            receivedAtMicros: 1_010);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_020,
            out QuicAckFrame frame));
        Assert.Equal(4UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);

        QuicAckRange earlierPacketRange = Assert.Single(frame.AdditionalRanges);
        Assert.Equal(0UL, earlierPacketRange.Gap);
        Assert.Equal(0UL, earlierPacketRange.AckRangeLength);
        Assert.Equal(2UL, earlierPacketRange.SmallestAcknowledged);
        Assert.Equal(2UL, earlierPacketRange.LargestAcknowledged);
    }
}
