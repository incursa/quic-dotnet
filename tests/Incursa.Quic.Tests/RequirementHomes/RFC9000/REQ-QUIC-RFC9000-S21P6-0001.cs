// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P6-0001">QUIC deployments SHOULD provide mitigations for the Slowloris attacks, such as increasing the maximum number of clients the server will allow, limiting the number of connections a single IP address is allowed to make, imposing restrictions on the minimum transfer speed a connection is allowed to have, and restricting the length of time an endpoint is allowed to stay connected.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S21P6-0001")]
public sealed class REQ_QUIC_RFC9000_S21P6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesSlowlorisMitigationsForDeployments()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-S21P6-0001");

        Assert.Equal("QUIC deployments SHOULD provide mitigations for the Slowloris attacks, such as increasing the maximum number of clients the server will allow, limiting the number of connections a single IP address is allowed to make, imposing restrictions on the minimum transfer speed a connection is allowed to have, and restricting the length of time an endpoint is allowed to stay connected.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 §21.6 RFC9000-S21.6-B3-P2-S1", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotClaimTransportRuntimeAutonomyForDeploymentPolicy()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-S21P6-0001");

        string statement = requirement.GetProperty("statement").GetString() ?? string.Empty;

        Assert.DoesNotContain("transport-runtime behavior", statement);
        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("hosted runner", statement);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToDeploymentMitigationExamples()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-S21P6-0001");

        string statement = requirement.GetProperty("statement").GetString() ?? string.Empty;

        Assert.Contains("maximum number of clients", statement);
        Assert.Contains("single IP address", statement);
        Assert.Contains("minimum transfer speed", statement);
        Assert.Contains("length of time", statement);
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
