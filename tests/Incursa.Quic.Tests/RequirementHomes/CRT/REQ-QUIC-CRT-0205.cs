// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0205")]
public sealed class REQ_QUIC_CRT_0205
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FocusedCompilerCorpusIsDeterministicAndRejectsEveryExpectedFailure()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentPlanCompiler.ps1");

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        JsonElement root = summary.RootElement;
        Assert.True(root.GetProperty("valid").GetBoolean());
        Assert.Equal(7, root.GetProperty("valid_plan_count").GetInt32());
        Assert.Equal(5, root.GetProperty("warning_plan_count").GetInt32());
        Assert.Equal(21, root.GetProperty("invalid_plan_count").GetInt32());
        Assert.Equal(6, root.GetProperty("invalid_manifest_or_validation_count").GetInt32());
        Assert.True(root.GetProperty("canonical_serialization_byte_equivalent").GetBoolean());
        Assert.True(root.GetProperty("repeated_hashes_identical").GetBoolean());
        Assert.True(root.GetProperty("self_hash_excluded").GetBoolean());
        Assert.True(root.GetProperty("unordered_arrays_normalized").GetBoolean());
        Assert.True(root.GetProperty("significant_order_preserved").GetBoolean());
        Assert.True(root.GetProperty("meaningful_changes_alter_hashes").GetBoolean());
        Assert.True(root.GetProperty("hash_roles_not_interchangeable").GetBoolean());
        Assert.Empty(root.GetProperty("failures").EnumerateArray());
    }
}
