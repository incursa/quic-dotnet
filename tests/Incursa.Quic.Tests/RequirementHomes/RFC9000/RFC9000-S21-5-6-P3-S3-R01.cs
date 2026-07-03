// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S21-5-6-P3-S3-R01">Endpoints SHOULD NOT refuse to use an address unless they have specific knowledge about the network indicating that sending datagrams to unvalidated addresses in a given range is not safe.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S21-5-6-P3-S3-R01")]
public sealed class REQ_QUIC_RFC9000_1470
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesAddressUseGuidance()
    {
        JsonElement requirement = GetRequirement("RFC9000-S21-5-6-P3-S3-R01");

        Assert.Equal("Endpoints SHOULD NOT refuse to use an address unless they have specific knowledge about the network indicating that sending datagrams to unvalidated addresses in a given range is not safe.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 21.5.6 RFC9000-S21P5P6-B3-P3-S3", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotClaimRuntimeAddressRefusal()
    {
        string statement = GetRequirement("RFC9000-S21-5-6-P3-S3-R01").GetProperty("statement").GetString() ?? string.Empty;

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime enforcement", statement);
        Assert.DoesNotContain("endpoint hardening orchestration", statement);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToNetworkKnowledgeGuidance()
    {
        string statement = GetRequirement("RFC9000-S21-5-6-P3-S3-R01").GetProperty("statement").GetString() ?? string.Empty;

        Assert.Contains("specific knowledge about the network", statement);
        Assert.Contains("unvalidated addresses", statement);
        Assert.Contains("not safe", statement);
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
