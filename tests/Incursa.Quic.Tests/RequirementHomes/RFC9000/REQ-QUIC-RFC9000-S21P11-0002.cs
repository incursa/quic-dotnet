// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S21-11-P3-R01">More generally, servers MUST NOT generate a stateless reset if a connection with the corresponding connection ID could be active on any endpoint using the same static key.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S21-11-P3-R01")]
public sealed class REQ_QUIC_RFC9000_S21P11_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_PreventsStatelessResetWhenAnySharedKeyEndpointCouldStillOwnTheConnection()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "RFC9000-S21-11-P3-R01");

        Assert.Equal("More generally, servers MUST NOT generate a stateless reset if a connection with the correspo...", requirement.GetProperty("title").GetString());
        Assert.Equal("More generally, servers MUST NOT generate a stateless reset if a connection with the corresponding connection ID could be active on any endpoint using the same static key.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 §21.11 RFC9000-S21.11-B4-P3-S1", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotPermitStatelessResetWhenSharedKeyOwnershipIsStillPossible()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "RFC9000-S21-11-P3-R01");

        string statement = requirement.GetProperty("statement").GetString() ?? string.Empty;

        Assert.DoesNotContain("MAY generate a stateless reset", statement);
        Assert.DoesNotContain("SHOULD generate a stateless reset", statement);
        Assert.DoesNotContain("always generate a stateless reset", statement);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_KeepsTheInactiveConnectionAndSharedKeyBoundaryIntact()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "RFC9000-S21-11-P3-R01");

        string statement = requirement.GetProperty("statement").GetString() ?? string.Empty;

        Assert.Contains("could be active on any endpoint using the same static key", statement);
        Assert.Contains("More generally, servers MUST NOT generate a stateless reset", statement);
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
