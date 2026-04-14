namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0013">Long header packets that contain CRYPTO frames MUST use shorter timers for acknowledgment.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0013")]
public sealed class REQ_QUIC_RFC9002_S3_0013
{
    [Theory]
    [InlineData((int)QuicPacketNumberSpace.Initial)]
    [InlineData((int)QuicPacketNumberSpace.Handshake)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordProcessedCryptoPacket_RequestsAnImmediateAckForLongHeaderSpaces(int packetNumberSpaceValue)
    {
        QuicPacketNumberSpace packetNumberSpace = (QuicPacketNumberSpace)packetNumberSpaceValue;

        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x06));

        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            packetNumberSpace,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(tracker.ShouldSendAckImmediately(packetNumberSpace));
        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            packetNumberSpace,
            nowMicros: 1_100,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordProcessedApplicationDataAckElicitingPacket_DoesNotUseTheShortAckTimer()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
        Assert.True(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            maxAckDelayMicros: 1_000));
    }
}
