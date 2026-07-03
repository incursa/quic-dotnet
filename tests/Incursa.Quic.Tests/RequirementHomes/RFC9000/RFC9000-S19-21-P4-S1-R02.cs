// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S19-21-P4-S1-R02")]
public sealed class REQ_QUIC_RFC9000_1381
{
    [Fact]
    [Requirement("RFC9000-S19-21-P4-S1-R02")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesAckGenerationForExtensionFrames()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("RFC9000-S19-21-P4-S1-R02");

        Assert.Equal("Extension frames MUST cause an ACK frame to be sent.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("RFC9000-S19-21-P4-S1-R02"));
    }

    [Fact]
    [Requirement("RFC9000-S19-21-P4-S1-R02")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnAckGenerationGuidanceIntoGeneralAckPolicy()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("RFC9000-S19-21-P4-S1-R02");

        Assert.DoesNotContain("all packets", statement);
        Assert.DoesNotContain("transport runtime behavior", statement);
        Assert.DoesNotContain("public API", statement);
    }

    [Fact]
    [Requirement("RFC9000-S19-21-P4-S1-R02")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToAckGenerationForExtensionFrames()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("RFC9000-S19-21-P4-S1-R02");

        Assert.Contains("Extension frames", statement);
        Assert.Contains("ACK frame", statement);
    }
}
