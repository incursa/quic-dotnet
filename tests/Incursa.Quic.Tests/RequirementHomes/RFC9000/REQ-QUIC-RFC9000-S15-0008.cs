namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S15-0008">A client MAY use one of these version numbers with the expectation that the server will initiate version negotiation.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S15-0008")]
public sealed class REQ_QUIC_RFC9000_S15_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldSendVersionNegotiation_AllowsReservedClientVersionsToElicitNegotiation()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.CreateReservedVersion(0x11223344),
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldSendVersionNegotiation_RejectsReservedClientVersionsWithoutServerSupport()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.CreateReservedVersion(0x11223344),
            []));
    }
}
