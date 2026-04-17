namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P2-0002">A receiver SHOULD send an ACK frame after receiving at least two ack-eliciting packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P2-0002")]
public sealed class REQ_QUIC_RFC9000_S13P2P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_RemainsFalseAfterOneAckElicitingPacketAndOneNonAckElicitingPacket()
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

        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_TurnsTrueAfterTheSecondAckElicitingPacketArrives()
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
    }
}
