namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1381")]
public sealed class REQ_QUIC_RFC9000_1381
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1381")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesAckGenerationForExtensionFrames()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-1381");

        Assert.Equal("Extension frames MUST cause an ACK frame to be sent.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-1381"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1381")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnAckGenerationGuidanceIntoGeneralAckPolicy()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1381");

        Assert.DoesNotContain("all packets", statement);
        Assert.DoesNotContain("transport runtime behavior", statement);
        Assert.DoesNotContain("public API", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1381")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToAckGenerationForExtensionFrames()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1381");

        Assert.Contains("Extension frames", statement);
        Assert.Contains("ACK frame", statement);
    }
}
