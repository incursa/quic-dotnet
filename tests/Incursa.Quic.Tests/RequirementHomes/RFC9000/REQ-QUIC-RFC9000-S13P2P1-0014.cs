namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0014">Packets marked with the ECN Congestion Experienced (CE) codepoint in the IP header SHOULD be acknowledged immediately.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0014")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordIncomingPacket_WithCongestionExperiencedCodepointRequiresImmediateAck()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 9,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            congestionExperienced: true);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_001,
            maxAckDelayMicros: 25_000));
        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_001,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordIncomingPacket_WithoutCongestionExperiencedCodepointKeepsApplicationDataDelayedAckEligible()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 9,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            congestionExperienced: false);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_001,
            maxAckDelayMicros: 25_000));
        Assert.True(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_001,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void MarkAckFrameSent_ClearsCongestionExperiencedImmediateAckUntilAnotherCePacketArrives()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 9,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            congestionExperienced: true);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_001,
            ackOnlyPacket: true);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            ackEliciting: true,
            receivedAtMicros: 1_002,
            congestionExperienced: true);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
    }
}
