namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0026">A Stateless Reset MUST use an entire UDP datagram starting with the first two bits of the packet header.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0026")]
public sealed class REQ_QUIC_RFC9000_S10P3_0026
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_UsesAFullUdpDatagram()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x80);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength + 1);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(datagram, token);
        Assert.Equal(QuicStatelessReset.MinimumDatagramLength + 1, datagram.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatStatelessResetDatagram_UsesTheSmallestFullUdpDatagram()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x80);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, QuicStatelessReset.MinimumDatagramLength);
        QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(datagram);
        QuicStatelessResetRequirementTestData.AssertTailTokenMatches(datagram, token);
        Assert.Equal(QuicStatelessReset.MinimumDatagramLength, datagram.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStatelessResetDatagram_RejectsDatagramsThatAreTooShortToBeFull()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x80);
        Span<byte> destination = stackalloc byte[QuicStatelessReset.MinimumDatagramLength - 1];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, QuicStatelessReset.MinimumDatagramLength - 1, destination, out _));
    }
}
