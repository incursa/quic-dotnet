// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0217")]
public sealed class REQ_QUIC_CRT_0217
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CloseoutCorpusAndFrozenBoundaryAreRetained()
    {
        string root = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string fixtures = Path.Combine(
            root,
            "tests",
            "fixtures",
            "adaptive-exp-evidence-closeout");

        Assert.True(Directory.GetFiles(fixtures, "*.json", SearchOption.AllDirectories).Length >= 39);
        using JsonDocument projection =
            JsonDocument.Parse(File.ReadAllText(Path.Combine(
                fixtures,
                "valid",
                "expected",
                "projection.json")));
        Assert.False(
            projection.RootElement
                .GetProperty("active_behavior_authorization")
                .GetBoolean());
        Assert.False(
            projection.RootElement
                .GetProperty("performance_acceptance_authorization")
                .GetBoolean());
        Assert.True(File.Exists(Path.Combine(
            root,
            "docs",
            "design",
            "adaptive-runtime-experiment-evidence-integrity-closeout.md")));
    }
}
