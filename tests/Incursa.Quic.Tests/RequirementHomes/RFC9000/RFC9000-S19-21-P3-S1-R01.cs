// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S19-21-P3-S1-R01")]
public sealed class RFC9000_S19_21_P3_S1_R01
{
    [Fact]
    [Requirement("RFC9000-S19-21-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesExtensionInteractionGuidance()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("RFC9000-S19-21-P3-S1-R01");

        Assert.Equal("Such extensions SHOULD define their interaction with previously defined extensions modifying the same protocol components.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("RFC9000-S19-21-P3-S1-R01"));
    }

    [Fact]
    [Requirement("RFC9000-S19-21-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnExtensionInteractionGuidanceIntoRuntimePolicy()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("RFC9000-S19-21-P3-S1-R01");

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime policy", statement);
        Assert.DoesNotContain("transport parameter", statement);
    }

    [Fact]
    [Requirement("RFC9000-S19-21-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToInteractionWithPreviousExtensions()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("RFC9000-S19-21-P3-S1-R01");

        Assert.Contains("previously defined extensions", statement);
        Assert.Contains("same protocol components", statement);
    }
}
