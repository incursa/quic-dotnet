// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0210")]
public sealed class REQ_QUIC_CRT_0210
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CatalogAuthorityAndCorrelationHardeningPass()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentHardening.ps1");

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        Assert.True(
            summary.RootElement.GetProperty("catalog_mapping_change_proof").GetBoolean());
        Assert.True(
            summary.RootElement.GetProperty("ambiguous_catalog_rejected").GetBoolean());
        Assert.True(
            summary.RootElement.GetProperty("filename_independent_warnings").GetBoolean());
        Assert.Equal(20, summary.RootElement.GetProperty("invalid_fixtures").GetInt32());
    }
}
