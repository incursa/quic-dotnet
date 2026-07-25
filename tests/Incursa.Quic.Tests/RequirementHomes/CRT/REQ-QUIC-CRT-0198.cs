// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0198")]
public sealed class REQ_QUIC_CRT_0198
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ArchitectureKeepsPlanningRuntimeAndMaterializationOwnershipSeparate()
    {
        string architecture = File.ReadAllText(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "docs/design/adaptive-runtime-experiment-control-architecture.md"));

        Assert.Contains("candidate_value", architecture, StringComparison.Ordinal);
        Assert.Contains("Actual runtime eligibility and mechanism events | Raw evidence", architecture, StringComparison.Ordinal);
        Assert.Contains("Actual behavior aggregates | Effective-behavior materialization", architecture, StringComparison.Ordinal);
        Assert.Contains("actuation_validation", architecture, StringComparison.Ordinal);
        Assert.Contains("profile_validation", architecture, StringComparison.Ordinal);
        Assert.Contains("Performance conclusions are prohibited", architecture, StringComparison.Ordinal);
    }
}
