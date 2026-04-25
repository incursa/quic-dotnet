namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0013">To assist loss detection at the sender, an endpoint SHOULD generate and send an ACK frame without delay when it receives an ack-eliciting packet that has a packet number less than another ack-eliciting packet that has been received, or when the packet has a packet number larger than the highest-numbered ack-eliciting packet that has been received and there are missing packets between that packet and this packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0013")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordIncomingPacket_OutOfOrderAckElicitingPacketRequiresImmediateAck()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 9,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_101,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordIncomingPacket_GapDetectingAckElicitingPacketRequiresImmediateAck()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 12,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.True(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_101,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordIncomingPacket_ContiguousAckElicitingPacketKeepsNormalDelayedAckScheduling()
    {
        QuicSenderFlowController sender = new(minimumAckElicitingPacketsBeforeDelayedAck: 3);

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            ackEliciting: true,
            receivedAtMicros: 1_100);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_101,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordIncomingPacket_NonAckElicitingGapDoesNotRequireImmediateAck()
    {
        QuicSenderFlowController sender = new();

        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            ackEliciting: true,
            receivedAtMicros: 1_000);
        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_050,
            ackOnlyPacket: true);
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 12,
            ackEliciting: false,
            receivedAtMicros: 1_100);

        Assert.False(sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_101,
            maxAckDelayMicros: 25_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RecordIncomingPacket_ClassifiesReorderedAndGapDetectingAckElicitingPackets()
    {
        for (int firstPacketNumber = 4; firstPacketNumber < 64; firstPacketNumber += 3)
        {
            for (int delta = -3; delta <= 4; delta++)
            {
                foreach (bool secondPacketAckEliciting in new[] { true, false })
                {
                    ulong first = (ulong)firstPacketNumber;
                    ulong second = (ulong)(firstPacketNumber + delta);
                    QuicSenderFlowController sender = new(minimumAckElicitingPacketsBeforeDelayedAck: 16);

                    sender.RecordIncomingPacket(
                        QuicPacketNumberSpace.ApplicationData,
                        first,
                        ackEliciting: true,
                        receivedAtMicros: 1_000);
                    sender.RecordIncomingPacket(
                        QuicPacketNumberSpace.ApplicationData,
                        second,
                        ackEliciting: secondPacketAckEliciting,
                        receivedAtMicros: 1_100);

                    bool expectedImmediateAck = secondPacketAckEliciting
                        && (second < first || second > first + 1);

                    Assert.Equal(
                        expectedImmediateAck,
                        sender.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
                }
            }
        }
    }
}
