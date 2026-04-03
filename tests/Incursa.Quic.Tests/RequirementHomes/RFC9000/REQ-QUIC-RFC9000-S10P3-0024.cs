namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3-0024")]
public sealed class REQ_QUIC_RFC9000_S10P3_0024
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_PlacesTheTokenInTheLastSixteenBytes()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x60);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(datagram, token);
    }
}
