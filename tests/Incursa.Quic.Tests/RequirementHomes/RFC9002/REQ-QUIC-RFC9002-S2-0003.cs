namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S2-0003")]
public sealed class REQ_QUIC_RFC9002_S2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ShouldNotIncludeAckFrameBeforeTheMaximumAckDelay()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_999,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void ShouldIncludeAckFrameWhenTheMaximumAckDelayElapses()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            maxAckDelayMicros: 1_000));
    }
}
