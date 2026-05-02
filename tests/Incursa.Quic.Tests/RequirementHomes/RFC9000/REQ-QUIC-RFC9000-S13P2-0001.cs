namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2-0001">Endpoints MUST acknowledge all packets they receive and process.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2-0001")]
public sealed class REQ_QUIC_RFC9000_S13P2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_EmitsEveryProcessedPacketAcrossNonContiguousRanges()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame frame));
        Assert.Equal(4UL, frame.LargestAcknowledged);
        Assert.Equal(0UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(0UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(0UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(2UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(2UL, frame.AdditionalRanges[0].LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_ReturnsFalseWithoutAnyProcessedPackets()
    {
        QuicAckGenerationState tracker = new();

        Assert.False(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out _));
    }
}
