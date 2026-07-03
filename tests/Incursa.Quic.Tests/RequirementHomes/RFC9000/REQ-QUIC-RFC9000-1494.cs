// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S22-1-2-P4-S1-R01">Applications to register codepoints in QUIC registries MAY include a requested codepoint as part of the registration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S22-1-2-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_1494
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_AllowsRequestedCodepointInRegistration()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "RFC9000-S22-1-2-P4-S1-R01");

        Assert.Equal("Allow requested codepoint values in registration applications", requirement.GetProperty("title").GetString());
        Assert.Equal("Applications to register codepoints in QUIC registries MAY include a requested codepoint as part of the registration.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC9000-S22P1P2-B4-P4-S1", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotRequireARequestedCodepointInRegistration()
    {
        JsonElement requirement = LoadRequirement();
        string statement = requirement.GetProperty("statement").GetString()!;

        Assert.Contains("MAY include a requested codepoint", statement);
        Assert.DoesNotContain("MUST include a requested codepoint", statement);
        Assert.DoesNotContain("MUST NOT omit", statement);
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
            .Single(entry => entry.GetProperty("id").GetString() == "RFC9000-S22-1-2-P4-S1-R01")
            .Clone();
    }
}
