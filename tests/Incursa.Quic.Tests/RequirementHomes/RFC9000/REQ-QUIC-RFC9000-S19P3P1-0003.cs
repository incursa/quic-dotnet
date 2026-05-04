namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P1-0003")]
public sealed class REQ_QUIC_RFC9000_S19P3P1_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_DecodesGapAsVariableLengthInteger()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.CreateAckFrameWithAdditionalRange(
                    largestAcknowledged: 100,
                    firstAckRange: 0,
                    gap: 0x40,
                    ackRangeLength: 0)));

        Assert.Equal(0x40UL, parsed.AdditionalRanges[0].Gap);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedGapVarint()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(10),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                [0x40]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_AcceptsTwoByteGapVarintAtBoundary()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(100),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.VarintWithLength(0x40, encodedLength: 2),
                QuicS19P3AckFrameTestSupport.Varint(0)));

        Assert.Equal(0x40UL, parsed.AdditionalRanges[0].Gap);
    }
}
