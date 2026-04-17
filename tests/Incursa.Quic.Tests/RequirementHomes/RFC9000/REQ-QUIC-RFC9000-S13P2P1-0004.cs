namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0004">An endpoint MUST acknowledge all ack-eliciting 0-RTT and 1-RTT packets within its advertised max_ack_delay.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0004")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_ReturnsTrueOnceTheApplicationDataAckDelayExpires()
    {
        QuicSenderFlowController sender = CreateSenderWithSingleApplicationDataPacket();

        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_001,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_RemainsFalseBeforeTheApplicationDataAckDelayExpires()
    {
        QuicSenderFlowController sender = CreateSenderWithSingleApplicationDataPacket();

        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_999,
            maxAckDelayMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_UsesTheExactApplicationDataAckDelayBoundary()
    {
        QuicSenderFlowController sender = CreateSenderWithSingleApplicationDataPacket();

        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            maxAckDelayMicros: 1_000));
    }

    private static QuicSenderFlowController CreateSenderWithSingleApplicationDataPacket()
    {
        QuicSenderFlowController sender = new();
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        return sender;
    }
}
