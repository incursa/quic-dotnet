// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0213")]
public sealed class REQ_QUIC_CRT_0213
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HardeningCorpusAndReviewPackageAreRetained()
    {
        string root = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string fixtures = Path.Combine(
            root,
            "tests",
            "fixtures",
            "adaptive-runtime-experiment-hardening");

        Assert.Equal(9, Directory.GetFiles(Path.Combine(fixtures, "valid"), "*.json").Length);
        Assert.Equal(6, Directory.GetFiles(Path.Combine(fixtures, "warning"), "*.json").Length);
        Assert.Equal(20, Directory.GetFiles(Path.Combine(fixtures, "invalid"), "*.json").Length);
        Assert.Equal(
            5,
            Directory.GetFiles(Path.Combine(fixtures, "projection-invalid"), "*.json").Length);
        using JsonDocument expectations =
            JsonDocument.Parse(File.ReadAllText(Path.Combine(fixtures, "expectations.json")));
        Assert.Equal(
            5,
            expectations.RootElement
                .GetProperty("projection_invalid")
                .EnumerateObject()
                .Count());
        Assert.True(File.Exists(Path.Combine(
            root,
            "docs",
            "testing",
            "adaptive-runtime-experiment-hardening-review-package-2026-07-25.md")));
    }
}
