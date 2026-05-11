namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P2-0003")]
public sealed class REQ_QUIC_RFC9000_S22P2_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S22P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReservedVersionPattern_IsExcludedFromAssignedVersionValues()
    {
        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(QuicVersionNegotiation.Version1));
        Assert.Equal((uint)0x0A1A2A3A, QuicVersionNegotiation.CreateReservedVersion(0x00112233));
    }
}
