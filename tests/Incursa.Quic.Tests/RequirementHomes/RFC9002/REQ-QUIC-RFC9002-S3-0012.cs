namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0012">Packets that contain no ack-eliciting frames MUST be acknowledged only along with ack-eliciting packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0012")]
public sealed class REQ_QUIC_RFC9002_S3_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordProcessedNonAckElicitingPacket_DoesNotRequestAnImmediateAck()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            1,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(tracker.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
    }
}
