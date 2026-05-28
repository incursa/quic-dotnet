// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1380")]
public sealed class REQ_QUIC_RFC9000_1380
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1380")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesCongestionControlledExtensionFrames()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-1380");

        Assert.Equal("Extension frames MUST be congestion controlled.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-1380"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1380")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotNameASpecificCongestionController()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1380");

        Assert.DoesNotContain("Cubic", statement, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BBR", statement, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runtime policy", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1380")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToCongestionControl()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1380");

        Assert.Contains("Extension frames", statement);
        Assert.Contains("congestion controlled", statement);
    }
}
