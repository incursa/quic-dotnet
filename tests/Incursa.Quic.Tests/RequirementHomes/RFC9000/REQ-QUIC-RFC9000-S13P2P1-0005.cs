namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0005">An endpoint MUST acknowledge all ack-eliciting Initial and Handshake packets immediately.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0005")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0005
{
    public static TheoryData<object> ImmediateAckPacketNumberSpaces => new()
    {
        QuicPacketNumberSpace.Initial,
        QuicPacketNumberSpace.Handshake,
    };

    [Theory]
    [MemberData(nameof(ImmediateAckPacketNumberSpaces))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldSendAckImmediately_ReturnsTrueForAckElicitingInitialAndHandshakePackets(
        object packetNumberSpaceValue)
    {
        QuicPacketNumberSpace packetNumberSpace = (QuicPacketNumberSpace)packetNumberSpaceValue;
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            packetNumberSpace,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.ShouldSendAckImmediately(packetNumberSpace));
    }

    [Theory]
    [MemberData(nameof(ImmediateAckPacketNumberSpaces))]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldSendAckImmediately_RemainsFalseForNonAckElicitingInitialAndHandshakePackets(
        object packetNumberSpaceValue)
    {
        QuicPacketNumberSpace packetNumberSpace = (QuicPacketNumberSpace)packetNumberSpaceValue;
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            packetNumberSpace,
            packetNumber: 1,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(sender.ShouldSendAckImmediately(packetNumberSpace));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ShouldSendAckImmediately_ReArmsAfterAnInitialAckFrameIsMarkedSent()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.Initial,
            sentAtMicros: 1_100,
            ackOnlyPacket: false);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.Initial,
            packetNumber: 2,
            ackEliciting: true,
            receivedAtMicros: 1_200);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.Initial));
    }
}
