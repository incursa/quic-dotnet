// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0208")]
public sealed class REQ_QUIC_CRT_0208
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProjectionRetainsAuthorityJoinsAndNegativeClassifications()
    {
        using JsonDocument projection =
            AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
                "tests/fixtures/adaptive-runtime-experiment-runtime-evidence/expected/projection/negative.retained_classification.fixture.projection.json");
        JsonElement root = projection.RootElement;

        Assert.Equal(
            "adaptive-runtime-experiment-evidence-projection-v1",
            root.GetProperty("schema_version").GetString());
        Assert.True(root.GetProperty("authority_chain").GetArrayLength() >= 5);
        Assert.NotEmpty(root.GetProperty("connection_epochs").EnumerateArray());
        Assert.NotEmpty(root.GetProperty("axis_decisions").EnumerateArray());
        Assert.NotEmpty(root.GetProperty("operation_evidence").EnumerateArray());
        Assert.Contains(
            root.GetProperty("classifications").EnumerateArray(),
            item => item.GetProperty("kind").GetString() == "negative"
                && item.GetProperty("retained").GetBoolean());
        Assert.False(root.GetProperty("active_behavior_authorization").GetBoolean());
        Assert.False(root.GetProperty("performance_acceptance_authorization").GetBoolean());
    }
}
