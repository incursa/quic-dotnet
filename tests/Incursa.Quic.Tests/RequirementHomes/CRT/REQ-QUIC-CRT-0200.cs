// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0200")]
public sealed class REQ_QUIC_CRT_0200
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalCatalogsPreserveFirstSliceFactsAndCompatibility()
    {
        using JsonDocument axes = AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
            "eng/adaptive-runtime/experiment-control/adaptive-runtime-policy-axis-contracts-v1.json");
        JsonElement[] contracts = axes.RootElement.GetProperty("axis_contracts").EnumerateArray().ToArray();
        Assert.Equal(3, contracts.Length);

        JsonElement sendTurn = Assert.Single(
            contracts,
            static contract =>
                contract.GetProperty("axis_id").GetString() == "application_send_turn_planning");
        Assert.Equal(
            2,
            sendTurn.GetProperty("selected_value_compatibility").GetArrayLength());
        Assert.All(
            sendTurn.GetProperty("selected_value_compatibility").EnumerateArray(),
            static mapping => Assert.Equal("verification_only", mapping.GetProperty("comparison_mode").GetString()));

        using JsonDocument behaviors = AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
            "eng/adaptive-runtime/experiment-control/adaptive-runtime-effective-behavior-catalog-v1.json");
        JsonElement sendTurnBehavior = Assert.Single(
            behaviors.RootElement.GetProperty("effective_behaviors").EnumerateArray(),
            static behavior =>
                behavior.GetProperty("axis_id").GetString() == "application_send_turn_planning");
        Assert.Equal(
            "behavior.application_send_turn_planning.legacy_priority_stable_sequence",
            sendTurnBehavior.GetProperty("effective_behavior_id").GetString());
        Assert.Equal(2, sendTurnBehavior.GetProperty("candidate_values").GetArrayLength());

        Assert.True(File.Exists(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "schemas/adaptive-runtime-policy-catalog-v1.schema.json")));
        Assert.True(File.Exists(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1")));
    }
}
