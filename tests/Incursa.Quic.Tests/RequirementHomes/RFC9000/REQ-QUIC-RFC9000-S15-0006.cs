namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S15-0006")]
public sealed class REQ_QUIC_RFC9000_S15_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IsReservedVersion_RecognizesTheReservedPattern()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x00112233);

        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.Equal((uint)0x0A1A2A3A, reservedVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IsReservedVersion_RejectsOrdinaryVersions()
    {
        Assert.False(QuicVersionNegotiation.IsReservedVersion(0x01020304));
    }
}
