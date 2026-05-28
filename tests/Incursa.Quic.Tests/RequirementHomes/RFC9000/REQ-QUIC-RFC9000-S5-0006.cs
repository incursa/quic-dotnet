// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5-0006")]
public sealed class REQ_QUIC_RFC9000_S5_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesZeroRttReplayProtectionProhibition()
    {
        var requirement = QuicRfc9000RequirementSpecSupport.GetRequirement("REQ-QUIC-RFC9000-S5-0006");

        Assert.Equal("0-RTT MUST NOT provide protection against replay attacks.", requirement.GetProperty("statement").GetString());
        Assert.Contains("#section-5", QuicRfc9000RequirementSpecSupport.GetUpstreamRef("REQ-QUIC-RFC9000-S5-0006"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnTheProhibitionIntoAnAntiReplayMechanism()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-S5-0006");

        Assert.DoesNotContain("anti-replay subsystem", statement);
        Assert.DoesNotContain("replay protection mechanism", statement);
        Assert.DoesNotContain("runtime enforcement", statement);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToZeroRttReplayProtection()
    {
        string statement = QuicRfc9000RequirementSpecSupport.GetStatement("REQ-QUIC-RFC9000-S5-0006");

        Assert.Contains("0-RTT", statement);
        Assert.Contains("must not provide protection", statement, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("replay attacks", statement);
    }
}
