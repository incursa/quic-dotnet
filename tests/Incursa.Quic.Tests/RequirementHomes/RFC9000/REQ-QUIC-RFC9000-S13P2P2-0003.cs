namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P2-0003">A receiver MAY process multiple available packets before determining whether to send an ACK frame in response.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P2-0003")]
public sealed class REQ_QUIC_RFC9000_S13P2P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_IncludesPacketsProcessedBeforeTheAckDecisionIsMade()
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
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            ackEliciting: true,
            receivedAtMicros: 1_020);

        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame frame));

        Assert.Equal(3UL, frame.LargestAcknowledged);
        Assert.Equal(2UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }
}
