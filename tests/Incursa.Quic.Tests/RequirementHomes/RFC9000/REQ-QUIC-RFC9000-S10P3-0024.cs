namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0024">The last 16 bytes of a Stateless Reset datagram MUST contain a stateless reset token.</workbench-requirement>
/// </workbench-requirements>
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
