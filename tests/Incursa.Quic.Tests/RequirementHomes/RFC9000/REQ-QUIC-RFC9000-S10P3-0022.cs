namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0022">Stateless Reset packets MUST set the fixed bits to 1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0022")]
public sealed class REQ_QUIC_RFC9000_S10P3_0022
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_SetsFixedBitsToOne()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x40);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        Assert.Equal(0, datagram[0] & 0x80);
        Assert.NotEqual(0, datagram[0] & 0x40);
    }
}
