// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0211")]
public sealed class REQ_QUIC_CRT_0211
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SetExpansionAndInteractionProofGateRemainExplicit()
    {
        using JsonDocument validation =
            AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
                "tests/fixtures/adaptive-runtime-experiment-hardening/linked/interaction.validation.v2.json");
        JsonElement root = validation.RootElement;

        Assert.Equal(
            "blocked_for_measurement",
            root.GetProperty("validation_classification").GetString());
        Assert.Equal(
            2,
            root.GetProperty("validation_warnings")
                .EnumerateArray()
                .Count(static item =>
                    item.GetProperty("warning_code").GetString() ==
                    "interaction_actuation_proof_missing"));
        Assert.Contains(
            root.GetProperty("expanded_planned_cells").EnumerateArray(),
            static cell =>
                cell.GetProperty("possible_effective_behavior_ids")
                    .GetArrayLength() > 1);
    }
}
