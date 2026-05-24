namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0756")]
public sealed class REQ_QUIC_RFC9000_0756
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_WhenAckHasNotBeenSentRecently()
    {
        QuicAckGenerationState ackState = new();
        ackState.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(ackState.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            maxAckDelayMicros: 200));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_DoesNotRepeatAckWhenOneWasSentRecently()
    {
        QuicAckGenerationState ackState = new();
        ackState.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        ackState.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_250,
            ackOnlyPacket: false);
        ackState.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_260);

        Assert.False(ackState.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_300,
            maxAckDelayMicros: 200));
    }
}
