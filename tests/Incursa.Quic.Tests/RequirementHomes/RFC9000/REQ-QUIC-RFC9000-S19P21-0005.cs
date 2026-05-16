namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P21-0005")]
public sealed class REQ_QUIC_RFC9000_S19P21_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P21-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesTransportParameterWillingnessSignal()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-S19P21-0005");

        Assert.Equal(
            "An endpoint MAY use a transport parameter to signal its willingness to receive extension frame types.",
            requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-S19P21-0005"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P21-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnWillingnessSignalIntoRuntimeCapability()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-S19P21-0005");

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime enforcement", statement);
        Assert.DoesNotContain("frame parser", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P21-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToTransportParameterSignaling()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-S19P21-0005");

        Assert.Contains("transport parameter", statement);
        Assert.Contains("willingness to receive", statement);
        Assert.Contains("extension frame types", statement);
    }
}
