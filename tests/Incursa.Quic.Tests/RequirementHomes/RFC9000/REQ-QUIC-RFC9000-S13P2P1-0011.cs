namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0011">When only non-ack-eliciting packets need to be acknowledged, an endpoint MAY choose not to send an ACK frame with outgoing frames until an ack-eliciting packet has been received.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0011")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_RemainsFalseWhenOnlyNonAckElicitingPacketsArePending()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: false,
            receivedAtMicros: 1_000);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_100,
            maxAckDelayMicros: 25_000));
        Assert.False(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_100,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ShouldIncludeAckFrameWithOutgoingPacket_StillDelaysNonAckElicitingOnlyPacketsAfterMaxAckDelay()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: false,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 6,
            ackEliciting: false,
            receivedAtMicros: 1_100);

        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 101_100,
            maxAckDelayMicros: 25_000));
        Assert.False(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 101_100,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ShouldIncludeAckFrameWithOutgoingPacket_DelaysNonAckElicitingOnlyPacketSets()
    {
        for (ulong firstPacketNumber = 1; firstPacketNumber <= 24; firstPacketNumber++)
        {
            QuicSenderFlowController sender = new();

            for (ulong offset = 0; offset < 4; offset++)
            {
                sender.RecordIncomingPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    firstPacketNumber + (offset * 2),
                    ackEliciting: false,
                    receivedAtMicros: 1_000 + offset);
            }

            Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
            Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 250_000,
                maxAckDelayMicros: 25_000));
            Assert.False(sender.CanSendAckOnlyPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 250_000,
                maxAckDelayMicros: 25_000));
        }
    }
}
