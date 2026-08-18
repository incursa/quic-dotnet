// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0215")]
public sealed class REQ_QUIC_CRT_0215
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CompositeIdentityAndClassificationMatrixAreExplicit()
    {
        using JsonDocument evidence =
            AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
                "tests/fixtures/adaptive-exp-evidence-closeout/valid/inputs/operation_evidence.json");
        JsonElement[] operations =
            evidence.RootElement.GetProperty("operations").EnumerateArray().ToArray();

        Assert.Contains(
            operations.GroupBy(static operation =>
                operation.GetProperty("operation_id").GetInt64()),
            static group => group.Count() > 1);

        using JsonDocument behavior =
            AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
                "tests/fixtures/adaptive-exp-evidence-closeout/valid/inputs/behavior_materialization.json");
        JsonElement[] identities =
            behavior.RootElement.GetProperty("derivations")
                .EnumerateArray()
                .Select(static row => row.GetProperty("operation_identity"))
                .ToArray();
        Assert.Equal(
            identities.Length,
            identities.Select(static identity =>
                identity.GetProperty("operation_key").GetString()).Distinct().Count());
        Assert.All(
            identities,
            static identity => Assert.Equal(
                1,
                identity.GetProperty("identity_version").GetInt32()));
    }
}
