// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0203")]
public sealed class REQ_QUIC_CRT_0203
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SendTurnLabelsCollapseToOneVerificationOnlyExpectedBehavior()
    {
        string planPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-experiment-plan-compiler/warning/send-verification.plan.json");
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Compile-AdaptiveRuntimeExperimentPlan.ps1",
                "-PlanPath",
                planPath,
                "-RepositoryRoot",
                repoRoot);

        Assert.Equal(0, result.ExitCode);
        using JsonDocument document = JsonDocument.Parse(result.Output);
        JsonElement root = document.RootElement;
        Assert.Equal("verification_only", root.GetProperty("validation_classification").GetString());
        Assert.Equal(2, root.GetProperty("cell_counts").GetProperty("configured").GetInt32());
        Assert.Equal(1, root.GetProperty("cell_counts").GetProperty("expected_effective").GetInt32());
        Assert.Contains(
            root.GetProperty("validation_warnings").EnumerateArray(),
            warning => warning.GetProperty("warning_code").GetString() ==
                "all_configured_values_collapse_to_one_expected_behavior");
    }
}
