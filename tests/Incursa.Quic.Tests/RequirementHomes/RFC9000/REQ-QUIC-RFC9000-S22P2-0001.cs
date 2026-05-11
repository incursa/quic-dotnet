namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P2-0001")]
public sealed class REQ_QUIC_RFC9000_S22P2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S22P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Version1_UsesTheAssignedCodepoint()
    {
        Assert.Equal((uint)0x00000001, QuicVersionNegotiation.Version1);
    }
}
