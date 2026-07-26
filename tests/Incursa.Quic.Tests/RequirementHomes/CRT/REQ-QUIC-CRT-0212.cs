// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0212")]
public sealed class REQ_QUIC_CRT_0212
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProjectionReferencesSeparateImmutableMaterializations()
    {
        using JsonDocument projection =
            AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
                "tests/fixtures/adaptive-runtime-experiment-hardening/expected/projection.json");
        JsonElement root = projection.RootElement;

        Assert.Equal(
            "adaptive-runtime-experiment-evidence-projection-v2",
            root.GetProperty("schema_version").GetString());
        Assert.Equal(
            "adaptive-runtime-effective-behavior-materialization-v2",
            root.GetProperty("behavior_materialization")
                .GetProperty("schema_version")
                .GetString());
        Assert.Equal(
            "adaptive-runtime-operation-outcome-materialization-v1",
            root.GetProperty("outcome_materialization")
                .GetProperty("schema_version")
                .GetString());
        Assert.NotEmpty(root.GetProperty("effective_behavior_aggregates").EnumerateArray());
        Assert.False(root.GetProperty("active_behavior_authorization").GetBoolean());
        Assert.False(
            root.GetProperty("performance_acceptance_authorization").GetBoolean());
    }
}
