// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0214")]
public sealed class REQ_QUIC_CRT_0214
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CatalogOutcomesAndAuthoritativeReleaseCorrelationPass()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentEvidenceIntegrityCloseout.ps1");

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        Assert.Equal(
            9,
            summary.RootElement.GetProperty("outcome_mapping_cases").GetInt32());
        Assert.Equal(
            9,
            summary.RootElement.GetProperty("evidence_invalid").GetInt32());
        Assert.False(
            summary.RootElement.GetProperty("active_behavior_authorized").GetBoolean());
    }
}
