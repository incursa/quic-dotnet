// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1376")]
public sealed class REQ_QUIC_RFC9000_1376
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1376")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesFramePeerUnderstandingRequirement()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-1376");

        Assert.Equal("An extension to QUIC that wishes to use a new type of frame MUST first ensure that a peer is able to understand the frame.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-1376"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1376")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnFrameNegotiationGuidanceIntoRuntimePolicy()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1376");

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime policy", statement);
        Assert.DoesNotContain("transport-runtime behavior", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1376")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToFutureExtensionFrameNegotiation()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1376");

        Assert.Contains("extension to QUIC", statement);
        Assert.Contains("new type of frame", statement);
        Assert.Contains("peer is able to understand the frame", statement);
    }
}
