namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P1-0005")]
public sealed class REQ_QUIC_RFC9000_S19P3P1_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_GapLeavesContiguousPacketsBeforePreviousRangeUnacknowledged()
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
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 6, sentAtMicros: 12_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsGapThatWouldMoveBeforePacketNumberZero()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_ZeroGapLeavesExactlyOnePacketUnacknowledged()
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
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 8, sentAtMicros: 12_000));
    }
}
