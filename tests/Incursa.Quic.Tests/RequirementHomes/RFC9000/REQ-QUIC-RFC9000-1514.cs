namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1514")]
public sealed class REQ_QUIC_RFC9000_1514
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1514")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void VersionNegotiation_UsesTheReservedCodepoint()
    {
        Assert.Equal(0u, QuicVersionNegotiation.VersionNegotiationVersion);
    }
}
