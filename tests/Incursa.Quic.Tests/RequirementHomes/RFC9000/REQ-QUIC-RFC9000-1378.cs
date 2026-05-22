namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1378")]
public sealed class REQ_QUIC_RFC9000_1378
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1378")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesMultiFrameSupportSignal()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-1378");

        Assert.Equal("One transport parameter MAY indicate support for one or more extension frame types.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-1378"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1378")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotRequireOneTransportParameterPerExtensionFrame()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1378");

        Assert.DoesNotContain("one transport parameter MUST", statement);
        Assert.DoesNotContain("runtime enforcement", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1378")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToSupportSignalForMultipleExtensionFrames()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1378");

        Assert.Contains("One transport parameter", statement);
        Assert.Contains("one or more extension frame types", statement);
    }
}
