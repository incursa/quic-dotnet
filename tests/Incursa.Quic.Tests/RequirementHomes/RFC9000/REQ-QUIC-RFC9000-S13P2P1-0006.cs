namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0006">Since packets containing only ACK frames are not congestion controlled, an endpoint MUST NOT send more than one such packet in response to receiving an ack-eliciting packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0006")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSendAckOnlyPacket_AllowsTheFirstAckOnlyPacketForAnAckElicitingApplicationDataPacket()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSendAckOnlyPacket_RejectsASecondAckOnlyPacketForTheSameAckElicitingApplicationDataPacket()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            maxAckDelayMicros: 1_000));

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_500,
            ackOnlyPacket: true);

        Assert.False(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_600,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanSendAckOnlyPacket_RearmsAfterTheNextAckElicitingApplicationDataPacketArrives()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_500,
            ackOnlyPacket: true);

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 8,
            ackEliciting: true,
            receivedAtMicros: 1_600);

        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_700,
            maxAckDelayMicros: 1_000));
    }
}
