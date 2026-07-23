// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0174")]
public sealed class REQ_QUIC_CRT_0174
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConstructionProvenanceUsesItsOwnCanonicalAxisAndPolicyContract()
    {
        using JsonDocument row = AdaptiveRuntimePolicyFixtureTestSupport.ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/construction-row.send-turn.forced.example.json");

        JsonElement root = row.RootElement;
        Assert.Equal("adaptive-runtime-policy-construction-dataset-v1", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("application_send_turn_planning", root.GetProperty("axisId").GetString());
        JsonElement state = root.GetProperty("constructionPolicyState");
        Assert.Equal("adaptive-runtime-application-send-turn-provenance-v1", state.GetProperty("provenanceContractVersion").GetString());
        Assert.Equal("application-send-turn-force-v1", state.GetProperty("ruleVersion").GetString());
        Assert.Equal("forced", state.GetProperty("selectionSource").GetString());
        Assert.True(root.GetProperty("workloadAnalysisOnly").GetProperty("excludedFromProductionFeatures").GetBoolean());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConstructionSchemaDoesNotPermitReceiveCreditEpochFields()
    {
        using JsonDocument schema = AdaptiveRuntimePolicyFixtureTestSupport.ReadRepositoryJson(
            "schemas/adaptive-runtime-policy-construction-dataset-v1.schema.json");

        JsonElement properties = schema.RootElement.GetProperty("properties");
        Assert.False(properties.TryGetProperty("preDecisionObservations", out _));
        Assert.False(properties.TryGetProperty("currentPolicyState", out _));
        Assert.False(properties.TryGetProperty("transitionState", out _));
        Assert.False(properties.TryGetProperty("epochIndex", out _));
        Assert.True(properties.GetProperty("axisId").GetProperty("const").GetString() == "application_send_turn_planning");
    }
}
