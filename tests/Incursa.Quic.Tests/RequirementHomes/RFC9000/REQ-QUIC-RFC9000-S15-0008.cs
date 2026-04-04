namespace Incursa.Quic.Tests;

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
