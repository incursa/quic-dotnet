// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1499">The experts MUST attempt to determine whether the codepoint is still in use.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1499")]
public sealed class REQ_QUIC_RFC9000_1499
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_UsesExpertReviewAttemptForCodepointInUseDetermination()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-1499");

        Assert.Equal("Determine whether codepoints remain in use", requirement.GetProperty("title").GetString());
        Assert.Equal("The experts MUST attempt to determine whether the codepoint is still in use.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 section 22.1.3 RFC9000-S22P1P3-B2-P2-S2", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1499")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotEquateReviewAttemptWithReclaimingTheCodepoint()
    {
        JsonElement requirement = LoadRequirement();
        string statement = requirement.GetProperty("statement").GetString()!;

        Assert.Contains("MUST attempt to determine", statement);
        Assert.DoesNotContain("MAY be removed", statement);
        Assert.DoesNotContain("MUST NOT be reclaimed", statement);
    }

    private static string GetRepoRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "src", "Incursa.Quic", "README.md")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root from the test output directory.");
    }

    private static JsonElement LoadRequirement()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        return document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-1499")
            .Clone();
    }
}
