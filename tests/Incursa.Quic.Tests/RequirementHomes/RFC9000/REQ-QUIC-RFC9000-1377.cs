// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1377")]
public sealed class REQ_QUIC_RFC9000_1377
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1377")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesTransportParameterWillingnessSignal()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-1377");

        Assert.Equal("An endpoint MAY use a transport parameter to signal its willingness to receive extension frame types.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-19.21", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-1377"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1377")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnWillingnessSignalIntoRuntimeCapability()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1377");

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime enforcement", statement);
        Assert.DoesNotContain("frame parser", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1377")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToTransportParameterSignaling()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-1377");

        Assert.Contains("transport parameter", statement);
        Assert.Contains("willingness to receive", statement);
        Assert.Contains("extension frame types", statement);
    }
}
