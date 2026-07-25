// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0202")]
public sealed class REQ_QUIC_CRT_0202
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CompilerOwnsLayeredPlanEligibilityWithoutRuntimeOperationEligibility()
    {
        string compiler = File.ReadAllText(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "eng/adaptive-runtime/Compile-AdaptiveRuntimeExperimentPlan.ps1"));

        Assert.Contains("stale_contract_reference", compiler, StringComparison.Ordinal);
        Assert.Contains("experiment_type_axis_count_invalid", compiler, StringComparison.Ordinal);
        Assert.Contains("axis_outside_experiment_family", compiler, StringComparison.Ordinal);
        Assert.Contains("cross_axis_constraint_violation", compiler, StringComparison.Ordinal);
        Assert.Contains("expected_capability_missing", compiler, StringComparison.Ordinal);
        Assert.Contains("active_behavior_unauthorized", compiler, StringComparison.Ordinal);
        Assert.DoesNotContain("BenchmarkDotNet", compiler, StringComparison.Ordinal);
    }
}
