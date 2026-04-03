namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3-0023")]
public sealed class REQ_QUIC_RFC9000_S10P3_0023
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_MakesTheLeadingBytesLookRandom()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x50);

        byte[] firstDatagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength + 8);
        byte[] secondDatagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength + 8);

        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(firstDatagram);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(secondDatagram);
        Assert.False(firstDatagram.AsSpan().SequenceEqual(secondDatagram));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatStatelessResetDatagram_StillMakesTheLeadingBytesLookRandomAtTheMinimumLength()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x50);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStatelessResetDatagram_RejectsDatagramsWithoutSpaceForRandomizedLeadingBytes()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x50);
        Span<byte> destination = stackalloc byte[QuicStatelessReset.MinimumDatagramLength - 1];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, QuicStatelessReset.MinimumDatagramLength - 1, destination, out _));
    }
}
