// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S22-1-3-P4-S1-R01">If no use of the codepoint was identified and no request was made to update the registration, the codepoint MAY be removed from the registry.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S22-1-3-P4-S1-R01")]
public sealed class RFC9000_S22_1_3_P4_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_UsesRemovalPermissionWhenNoUseIsIdentified()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "RFC9000-S22-1-3-P4-S1-R01");

        Assert.Equal("Allow removal when no use is identified", requirement.GetProperty("title").GetString());
        Assert.Equal("If no use of the codepoint was identified and no request was made to update the registration, the codepoint MAY be removed from the registry.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 section 22.1.3 RFC9000-S22P1P3-B4-P4-S1", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [Requirement("RFC9000-S22-1-3-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotAllowRemovalWhenUseOrUpdateRequestExists()
    {
        JsonElement requirement = LoadRequirement();
        string statement = requirement.GetProperty("statement").GetString()!;

        Assert.Contains("If no use", statement);
        Assert.Contains("no request", statement);
        Assert.DoesNotContain("MUST be removed", statement);
        Assert.DoesNotContain("even if", statement);
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
            .Single(entry => entry.GetProperty("id").GetString() == "RFC9000-S22-1-3-P4-S1-R01")
            .Clone();
    }
}
