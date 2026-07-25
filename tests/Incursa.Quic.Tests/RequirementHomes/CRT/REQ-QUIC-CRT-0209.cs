// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0209")]
public sealed class REQ_QUIC_CRT_0209
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FixtureCorpusHasStableClosedExpectedClassifications()
    {
        string root = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string fixtureRoot = Path.Combine(
            root,
            "tests",
            "fixtures",
            "adaptive-runtime-experiment-runtime-evidence");
        Assert.Equal(16, Directory.GetFiles(Path.Combine(fixtureRoot, "valid"), "*.json").Length);
        Assert.Equal(4, Directory.GetFiles(Path.Combine(fixtureRoot, "warning"), "*.json").Length);
        Assert.Equal(21, Directory.GetFiles(Path.Combine(fixtureRoot, "invalid"), "*.json").Length);

        using JsonDocument expectations = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(fixtureRoot, "expectations.json")));
        Assert.Equal(
            21,
            expectations.RootElement.GetProperty("invalid").EnumerateObject().Count());
        Assert.Equal(
            4,
            expectations.RootElement.GetProperty("warning").EnumerateObject().Count());
        Assert.True(File.Exists(Path.Combine(
            root,
            "docs",
            "testing",
            "adaptive-runtime-experiment-runtime-evidence-2026-07-25.md")));
    }
}
