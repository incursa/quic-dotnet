// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0207")]
public sealed class REQ_QUIC_CRT_0207
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MaterializerRecomputesAllFixturesWithClosedResults()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentRuntimeEvidence.ps1");

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        Assert.Equal(3, summary.RootElement.GetProperty("schemas_validated").GetInt32());
        Assert.Equal(16, summary.RootElement.GetProperty("valid_fixtures").GetInt32());
        Assert.Equal(5, summary.RootElement.GetProperty("warning_fixtures").GetInt32());
        Assert.Equal(24, summary.RootElement.GetProperty("invalid_fixtures").GetInt32());
        Assert.Equal(
            16,
            summary.RootElement
                .GetProperty("deterministic_materialization_and_projection_runs")
                .GetInt32());
        Assert.Empty(summary.RootElement.GetProperty("failures").EnumerateArray());
    }
}
