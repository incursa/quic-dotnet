namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P4-0006")]
public sealed class REQ_QUIC_RFC9000_S22P4_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S22P4-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FrameRegistry_DescribesFormatAndSemanticsOfPermanentFrameFields()
    {
        foreach ((_, _, string fieldSemantics) in QuicFrameRegistryProofSupport.PermanentFrameTypes)
        {
            Assert.NotEmpty(fieldSemantics);
            Assert.Contains(' ', fieldSemantics);
        }
    }
}
