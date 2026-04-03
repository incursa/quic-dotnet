namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3-0008")]
public sealed class REQ_QUIC_RFC9000_S10P3_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_ExposesAtLeastThirtyEightUnpredictableBits()
    {
        Assert.Equal(38, QuicStatelessReset.MinimumUnpredictableBits);
        Assert.Equal(5, QuicStatelessReset.MinimumUnpredictableBytes);

        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength + 1);

        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatStatelessResetDatagram_UsesTheMinimumThirtyEightBitBoundary()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStatelessResetDatagram_RejectsDatagramsBelowTheThirtyEightBitBoundary()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        Span<byte> destination = stackalloc byte[QuicStatelessReset.MinimumDatagramLength - 1];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, QuicStatelessReset.MinimumDatagramLength - 1, destination, out _));
    }
}
