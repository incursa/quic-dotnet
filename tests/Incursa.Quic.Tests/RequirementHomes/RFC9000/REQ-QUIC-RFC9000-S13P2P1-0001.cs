namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0001">Ack-eliciting packets MUST be acknowledged at least once within the maximum delay the endpoint communicated using the max_ack_delay transport parameter.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0001")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldIncludeAckFrameWithOutgoingPacket_ReturnsTrueOnceTheMaxAckDelayExpires()
    {
        QuicAckGenerationState tracker = CreateTrackerWithSingleAckElicitingPacket();

        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2001,
            maxAckDelayMicros: 1000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ShouldIncludeAckFrameWithOutgoingPacket_RemainsFalseBeforeTheMaxAckDelayExpires()
    {
        QuicAckGenerationState tracker = CreateTrackerWithSingleAckElicitingPacket();

        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1999,
            maxAckDelayMicros: 1000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void ShouldIncludeAckFrameWithOutgoingPacket_UsesTheExactMaxAckDelayBoundary()
    {
        QuicAckGenerationState tracker = CreateTrackerWithSingleAckElicitingPacket();

        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2000,
            maxAckDelayMicros: 1000));
    }

    private static QuicAckGenerationState CreateTrackerWithSingleAckElicitingPacket()
    {
        QuicAckGenerationState tracker = new();
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1000);

        return tracker;
    }
}
