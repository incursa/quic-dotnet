namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
public sealed class REQ_QUIC_RFC9000_S19P3_0015
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_ReportsLargestAcknowledgedPacketNumber()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(largestAcknowledged: 17));

        Assert.Equal(17UL, parsed.LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsFirstAckRangeGreaterThanLargestAcknowledged()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(largestAcknowledged: 3, firstAckRange: 4));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0015")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_AcceptsLargestAcknowledgedPacketZero()
    {
        QuicAckFrame parsed = QuicS19P3AckFrameTestSupport.ParseAckFrame(
            QuicS19P3AckFrameTestSupport.MinimalAckFramePayload(largestAcknowledged: 0, firstAckRange: 0));

        Assert.Equal(0UL, parsed.LargestAcknowledged);
    }
}
