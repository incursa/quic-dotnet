namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
public sealed class REQ_QUIC_RFC9000_S6P3_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P3-0001">Endpoints MAY add reserved versions to any field where unknown or unsupported versions are ignored to test that a peer correctly ignores the value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void IsReservedVersion_UsesTheReservedPattern()
    {
        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(0x01020304));
        Assert.Equal((uint)0x0A1A2A3A, QuicVersionNegotiation.CreateReservedVersion(0x00112233));
    }
}
