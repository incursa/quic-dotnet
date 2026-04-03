namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3-0025")]
public sealed class REQ_QUIC_RFC9000_S10P3_0025
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void MinimumUnpredictableBits_ExposesTheThirtyEightBitFloor()
    {
        Assert.Equal(38, QuicStatelessReset.MinimumUnpredictableBits);
        Assert.Equal(5, QuicStatelessReset.MinimumUnpredictableBytes);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength + QuicStatelessReset.MinimumUnpredictableBytes, QuicStatelessReset.MinimumDatagramLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void MinimumUnpredictableBits_AreSatisfiedAtTheBoundaryDatagramLength()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x70);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void MinimumUnpredictableBits_RejectsDatagramsShorterThanTheBoundary()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x70);
        Span<byte> destination = stackalloc byte[QuicStatelessReset.MinimumDatagramLength - 1];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, QuicStatelessReset.MinimumDatagramLength - 1, destination, out _));
    }
}
