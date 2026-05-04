namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
public sealed class REQ_QUIC_RFC9000_S19P3_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_DecodesLargestAcknowledgedAsVariableLengthInteger()
    {
        byte[] encoded = QuicS19P3AckFrameTestSupport.FormatAckFrame(
            QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(0x40));

        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(encoded);

        Assert.Equal(0x40UL, parsed.LargestAcknowledged);
        Assert.Equal(0x40, encoded[1] & 0xC0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedLargestAcknowledgedVarint()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects([0x02, 0x40]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0010")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatAckFrame_PreservesMaximumLargestAcknowledgedVarintValue()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.FormatAckFrame(
                QuicS19P3AckFrameTestSupport.CreateSinglePacketAckFrame(QuicVariableLengthInteger.MaxValue)));

        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.LargestAcknowledged);
    }
}
