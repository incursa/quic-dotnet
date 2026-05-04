namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P1-0009")]
public sealed class REQ_QUIC_RFC9000_S19P3P1_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_GapIdentifiesPacketsThatAreNotAcknowledged()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 8,
            last: 10);

        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 0,
            ackRangeLength: 0);

        Assert.True(sender.TryProcessAckFrame(QuicPacketNumberSpace.ApplicationData, frame, ackReceivedAtMicros: 11_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 12_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_DoesNotTreatGapPacketAsAcknowledged()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 8,
            last: 10);

        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 0,
            ackRangeLength: 0);

        Assert.True(sender.TryProcessAckFrame(QuicPacketNumberSpace.ApplicationData, frame, ackReceivedAtMicros: 11_000));
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 8, sentAtMicros: 12_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 12_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0009")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_LargerGapIdentifiesLargerUnacknowledgedRun()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 6,
            last: 10);

        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 2,
            ackRangeLength: 0);

        Assert.True(sender.TryProcessAckFrame(QuicPacketNumberSpace.ApplicationData, frame, ackReceivedAtMicros: 11_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 9, sentAtMicros: 12_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 8, sentAtMicros: 12_000));
        Assert.True(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 7, sentAtMicros: 12_000));
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 6, sentAtMicros: 12_000));
    }
}
