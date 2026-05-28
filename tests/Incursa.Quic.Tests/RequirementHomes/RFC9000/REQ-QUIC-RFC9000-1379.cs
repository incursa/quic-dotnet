// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1379")]
public sealed class REQ_QUIC_RFC9000_1379
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1379")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesExtensionInteractionGuidance()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-1379");

        Assert.Equal("Such extensions SHOULD define their interaction with previously defined extensions modifying the same protocol components.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-1379"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1379")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnExtensionInteractionGuidanceIntoRuntimePolicy()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1379");

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime policy", statement);
        Assert.DoesNotContain("transport parameter", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1379")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToInteractionWithPreviousExtensions()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1379");

        Assert.Contains("previously defined extensions", statement);
        Assert.Contains("same protocol components", statement);
    }
}
