namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S3-0017")]
public sealed class REQ_QUIC_RFC9002_S3_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void RecordProcessedPaddingPacket_DoesNotRequestAnImmediateAck()
    {
        QuicAckGenerationState tracker = new();

        bool paddingIsAckEliciting = QuicFrameCodec.IsAckElicitingFrameType(0x00);
        Assert.False(paddingIsAckEliciting);

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: paddingIsAckEliciting,
            receivedAtMicros: 1_000);

        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
    }
}
