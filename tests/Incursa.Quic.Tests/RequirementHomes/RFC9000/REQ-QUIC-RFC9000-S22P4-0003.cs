namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P4-0003")]
public sealed class REQ_QUIC_RFC9000_S22P4_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S22P4-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FrameRegistry_IncludesTheFrameTypeNameField()
    {
        foreach ((_, string frameTypeName, _) in QuicFrameRegistryProofSupport.PermanentFrameTypes)
        {
            Assert.NotEmpty(frameTypeName);
        }
    }
}
