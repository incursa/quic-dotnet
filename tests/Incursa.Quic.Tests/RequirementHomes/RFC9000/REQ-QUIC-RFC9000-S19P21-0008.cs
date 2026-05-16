namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P21-0008")]
public sealed class REQ_QUIC_RFC9000_S19P21_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P21-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesCongestionControlledExtensionFrames()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-S19P21-0008");

        Assert.Equal("Extension frames MUST be congestion controlled.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-S19P21-0008"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P21-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotNameASpecificCongestionController()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-S19P21-0008");

        Assert.DoesNotContain("Cubic", statement, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BBR", statement, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runtime policy", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P21-0008")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToCongestionControl()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-S19P21-0008");

        Assert.Contains("Extension frames", statement);
        Assert.Contains("congestion controlled", statement);
    }
}
