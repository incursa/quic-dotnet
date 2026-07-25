// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0199")]
public sealed class REQ_QUIC_CRT_0199
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatorProvesSchemaHashAndCanonicalizationContracts()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1");

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        JsonElement root = summary.RootElement;
        Assert.True(root.GetProperty("valid").GetBoolean());
        Assert.Equal(8, root.GetProperty("schema_count").GetInt32());
        Assert.True(root.GetProperty("canonical_serialization_byte_equivalent").GetBoolean());
        Assert.True(root.GetProperty("repeated_hashes_identical").GetBoolean());
        Assert.True(root.GetProperty("content_hashes_valid").GetBoolean());
        Assert.True(root.GetProperty("reference_resolution_valid").GetBoolean());
    }
}
