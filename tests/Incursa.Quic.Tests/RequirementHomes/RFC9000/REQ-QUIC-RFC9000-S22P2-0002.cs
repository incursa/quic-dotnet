namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P2-0002")]
public sealed class REQ_QUIC_RFC9000_S22P2_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S22P2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void VersionNegotiation_UsesTheReservedCodepoint()
    {
        Assert.Equal(0u, QuicVersionNegotiation.VersionNegotiationVersion);
    }
}
