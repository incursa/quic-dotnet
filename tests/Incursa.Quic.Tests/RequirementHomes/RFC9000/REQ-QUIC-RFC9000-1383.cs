// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1383")]
public sealed class REQ_QUIC_RFC9000_1383
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1383")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesExtensionFrameFlowControlExclusion()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-1383");

        Assert.Equal("Extension frames MUST NOT be included in flow control unless specified in the extension.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-1383"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1383")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTreatExtensionFramesAsFlowControlledByDefault()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1383");

        Assert.DoesNotContain("every extension frame", statement);
        Assert.DoesNotContain("all packet data", statement);
        Assert.DoesNotContain("runtime policy", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1383")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToFlowControlExclusion()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1383");

        Assert.Contains("Extension frames MUST NOT be included in flow control", statement);
        Assert.Contains("unless specified in the extension", statement);
    }
}
