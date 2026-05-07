namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P4-0006")]
public sealed class REQ_QUIC_RFC9000_S22P4_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FrameRegistrations_DescribeFieldFormatAndSemantics()
    {
        foreach ((_, _, _, string fieldDescription) in QuicFrameRegistryProofSupport.DefinedFrameRegistrations)
        {
            Assert.NotEmpty(fieldDescription);
            Assert.True(fieldDescription.Length >= 20);
            Assert.True(fieldDescription.Contains("field", StringComparison.OrdinalIgnoreCase));
            Assert.EndsWith(".", fieldDescription);
        }
    }
}
