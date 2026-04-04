namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S15-0002")]
public sealed class REQ_QUIC_RFC9000_S15_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void VersionNegotiationVersion_UsesTheReservedZeroValue()
    {
        Assert.Equal(0u, QuicVersionNegotiation.VersionNegotiationVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldSendVersionNegotiation_RejectsTheReservedZeroVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.VersionNegotiationVersion,
            [QuicVersionNegotiation.Version1]));
    }
}
