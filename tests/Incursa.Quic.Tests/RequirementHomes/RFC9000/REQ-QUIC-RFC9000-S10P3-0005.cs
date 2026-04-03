namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3-0005")]
public sealed class REQ_QUIC_RFC9000_S10P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_WritesTheFigure10Layout()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(datagram, token);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStatelessResetDatagram_RejectsDatagramsWithoutRoomForTheToken()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        Span<byte> destination = stackalloc byte[QuicStatelessReset.MinimumDatagramLength - 1];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, QuicStatelessReset.MinimumDatagramLength, destination, out _));
    }
}
