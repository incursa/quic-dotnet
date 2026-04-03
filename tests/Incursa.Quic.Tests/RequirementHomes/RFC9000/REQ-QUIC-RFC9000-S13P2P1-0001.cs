namespace Incursa.Quic.Tests;

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
