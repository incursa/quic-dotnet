// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0201")]
public sealed class REQ_QUIC_CRT_0201
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidatorRejectsEveryExpectedInvalidFixtureDeterministically()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeExperimentControl.ps1");

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        JsonElement root = summary.RootElement;
        Assert.True(root.GetProperty("valid").GetBoolean());
        Assert.Equal(15, root.GetProperty("invalid_fixture_count").GetInt32());
        Assert.Equal(0, root.GetProperty("invalid_fixture_failures").GetInt32());
        Assert.True(root.GetProperty("unknown_field_rejected").GetBoolean());
        Assert.Empty(root.GetProperty("failures").EnumerateArray());
    }
}
