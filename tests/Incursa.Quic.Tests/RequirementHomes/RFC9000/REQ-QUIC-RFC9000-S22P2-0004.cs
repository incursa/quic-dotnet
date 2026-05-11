namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P2-0004")]
public sealed class REQ_QUIC_RFC9000_S22P2_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S22P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReservedVersionPattern_RemainsReservedWhenSynthesized()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);

        Assert.True(QuicVersionNegotiation.IsReservedVersion(reservedVersion));
        Assert.NotEqual(QuicVersionNegotiation.VersionNegotiationVersion, reservedVersion);
        Assert.NotEqual(QuicVersionNegotiation.Version1, reservedVersion);
    }
}
