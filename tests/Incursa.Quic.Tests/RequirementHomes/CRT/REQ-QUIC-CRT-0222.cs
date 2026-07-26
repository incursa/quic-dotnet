// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0218")]
[Requirement("REQ-QUIC-CRT-0219")]
[Requirement("REQ-QUIC-CRT-0220")]
[Requirement("REQ-QUIC-CRT-0221")]
[Requirement("REQ-QUIC-CRT-0222")]
public sealed class REQ_QUIC_CRT_0222
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IndependentCandidateProofPackagesValidateDeterministically()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeIndependentActuationProof.ps1");

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        Assert.Equal(
            2,
            summary.RootElement.GetProperty("valid_proof_candidates").GetInt32());
        Assert.Equal(
            10,
            summary.RootElement.GetProperty("candidate_operations").GetInt32());
        Assert.Equal(
            5,
            summary.RootElement.GetProperty("candidate_releases").GetInt32());
        Assert.Equal(
            17,
            summary.RootElement.GetProperty("negative_cases").GetInt32());
        Assert.Equal(
            "candidate",
            summary.RootElement.GetProperty("review_status").GetString());
        Assert.True(
            summary.RootElement.GetProperty("measurement_frozen").GetBoolean());
        Assert.False(
            summary.RootElement.GetProperty(
                "interaction_execution_performed").GetBoolean());
        Assert.False(
            summary.RootElement.GetProperty(
                "active_behavior_authorized").GetBoolean());
    }
}
