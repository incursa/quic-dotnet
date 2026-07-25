// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0204")]
public sealed class REQ_QUIC_CRT_0204
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CompiledManifestShapeLinksPostBuildIdentityAndKeepsAuthorizationFalse()
    {
        using JsonDocument manifest = AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-experiment-plan-compiler/valid/compiled-manifest.fixture.json");
        JsonElement root = manifest.RootElement;

        Assert.Equal(64, root.GetProperty("source_plan_ref").GetProperty("content_sha256").GetString()!.Length);
        Assert.Equal(64, root.GetProperty("source_validation_ref").GetProperty("content_sha256").GetString()!.Length);
        Assert.Equal(40, root.GetProperty("source_commit").GetString()!.Length);
        Assert.Equal(64, root.GetProperty("binary_provenance")[0].GetProperty("content_sha256").GetString()!.Length);
        Assert.Equal(64, root.GetProperty("runner_identity").GetProperty("content_sha256").GetString()!.Length);
        Assert.True(root.GetProperty("host_fingerprint").TryGetProperty("fingerprint_id", out _));
        Assert.True(root.GetProperty("host_capabilities").TryGetProperty("resolved_capabilities", out _));
        Assert.False(root.GetProperty("active_behavior_authorization").GetBoolean());
        Assert.False(root.GetProperty("performance_acceptance_authorization").GetBoolean());
    }
}
