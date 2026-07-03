// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S21-5-P8-S2-R01">Any future extension that allows server migration MUST also define countermeasures for forgery attacks.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S21-5-P8-S2-R01")]
public sealed class REQ_QUIC_RFC9000_1454
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesServerMigrationForgeryCountermeasures()
    {
        JsonElement requirement = GetRequirement("RFC9000-S21-5-P8-S2-R01");

        Assert.Equal("Any future extension that allows server migration MUST also define countermeasures for forgery attacks.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 21.5 RFC9000-S21P5-B8-P8-S2", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTurnGuidanceIntoRuntimePolicy()
    {
        string statement = GetRequirement("RFC9000-S21-5-P8-S2-R01").GetProperty("statement").GetString() ?? string.Empty;

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime enforcement", statement);
        Assert.DoesNotContain("transport-runtime behavior", statement);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToFutureExtensionGuidance()
    {
        string statement = GetRequirement("RFC9000-S21-5-P8-S2-R01").GetProperty("statement").GetString() ?? string.Empty;

        Assert.Contains("future extension", statement);
        Assert.Contains("server migration", statement);
        Assert.Contains("forgery attacks", statement);
        Assert.Contains("MUST also define countermeasures", statement);
    }

    private static JsonElement GetRequirement(string requirementId)
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        return document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == requirementId)
            .Clone();
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
}
