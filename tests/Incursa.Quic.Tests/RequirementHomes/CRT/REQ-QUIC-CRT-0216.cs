// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0216")]
public sealed class REQ_QUIC_CRT_0216
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProjectionCarriesAllFifteenImmutableAuthorities()
    {
        using JsonDocument projection =
            AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
                "tests/fixtures/adaptive-runtime-experiment-evidence-integrity-closeout/valid/expected/projection.json");
        JsonElement root = projection.RootElement;

        Assert.Equal(
            "adaptive-runtime-experiment-evidence-projection-v3",
            root.GetProperty("schema_version").GetString());
        JsonElement[] authority =
            root.GetProperty("authority_chain").EnumerateArray().ToArray();
        Assert.Equal(15, authority.Length);
        Assert.Equal(
            15,
            authority.Select(static item =>
                item.GetProperty("document_id").GetString()).Distinct().Count());
        Assert.Equal(
            "adaptive-runtime-effective-behavior-materialization-v3",
            root.GetProperty("behavior_materialization")
                .GetProperty("schema_version")
                .GetString());
        Assert.Equal(
            "adaptive-runtime-operation-outcome-materialization-v2",
            root.GetProperty("outcome_materialization")
                .GetProperty("schema_version")
                .GetString());
    }
}
