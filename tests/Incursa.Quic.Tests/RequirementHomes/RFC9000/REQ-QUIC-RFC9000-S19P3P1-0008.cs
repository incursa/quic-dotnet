namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P1-0008")]
public sealed class REQ_QUIC_RFC9000_S19P3P1_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BuildAckRange_LargerAckRangeLengthProducesLowerSmallestPacketNumber()
    {
        QuicAckRange onePacketRange = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged: 20, gap: 0, ackRangeLength: 0);
        QuicAckRange fourPacketRange = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged: 20, gap: 0, ackRangeLength: 3);

        Assert.Equal(onePacketRange.LargestAcknowledged, fourPacketRange.LargestAcknowledged);
        Assert.True(fourPacketRange.SmallestAcknowledged < onePacketRange.SmallestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BuildAckRange_SmallerAckRangeLengthDoesNotReachAsLow()
    {
        QuicAckRange shortRange = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged: 20, gap: 0, ackRangeLength: 1);
        QuicAckRange longRange = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged: 20, gap: 0, ackRangeLength: 4);

        Assert.True(shortRange.SmallestAcknowledged > longRange.SmallestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0008")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void BuildAckRange_ZeroLengthRangeKeepsSmallestEqualToLargest()
    {
        QuicAckRange range = QuicFrameTestData.BuildAckRange(previousSmallestAcknowledged: 20, gap: 0, ackRangeLength: 0);

        Assert.Equal(range.LargestAcknowledged, range.SmallestAcknowledged);
    }
}
