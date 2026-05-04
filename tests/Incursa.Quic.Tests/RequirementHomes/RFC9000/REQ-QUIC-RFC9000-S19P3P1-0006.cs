namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P1-0006")]
public sealed class REQ_QUIC_RFC9000_S19P3P1_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_AckRangeLengthAcknowledgesContiguousPacketsBeforeComputedLargest()
    {
        QuicSenderFlowController sender = new();
        QuicS19P3AckFrameTestSupport.RecordSentPackets(
            sender,
            QuicPacketNumberSpace.ApplicationData,
            first: 5,
            last: 10);

        QuicAckFrame frame = QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
            largestAcknowledged: 10,
            firstAckRange: 0,
            gap: 1,
            ackRangeLength: 2);

        Assert.True(sender.TryProcessAckFrame(QuicPacketNumberSpace.ApplicationData, frame, ackReceivedAtMicros: 11_000));
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 5, sentAtMicros: 12_000));
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, packetNumber: 7, sentAtMicros: 12_000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsAckRangeLengthThatWouldExtendBeforePacketNumberZero()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(3),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(3)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_ZeroAckRangeLengthAcknowledgesOnlyComputedLargest()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
                    largestAcknowledged: 10,
                    firstAckRange: 0,
                    gap: 0,
                    ackRangeLength: 0)));

        Assert.Equal(parsed.AdditionalRanges[0].LargestAcknowledged, parsed.AdditionalRanges[0].SmallestAcknowledged);
    }
}
