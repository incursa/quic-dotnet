using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1473">Endpoints MAY retire connection IDs containing patterns known to be problematic without using them.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1473")]
public sealed class REQ_QUIC_RFC9000_1473
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesProblematicCidRetirementGuidance()
    {
        JsonElement requirement = GetRequirement("REQ-QUIC-RFC9000-1473");

        Assert.Equal("Endpoints MAY retire connection IDs containing patterns known to be problematic without using them.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 21.5.6 RFC9000-S21P5P6-B5-P5-S4", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotClaimPublicPolicyAutomation()
    {
        string statement = GetRequirement("REQ-QUIC-RFC9000-1473").GetProperty("statement").GetString() ?? string.Empty;

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime enforcement", statement);
        Assert.DoesNotContain("endpoint hardening orchestration", statement);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToProblematicCidHygiene()
    {
        string statement = GetRequirement("REQ-QUIC-RFC9000-1473").GetProperty("statement").GetString() ?? string.Empty;

        Assert.Contains("retire connection IDs", statement);
        Assert.Contains("patterns known to be problematic", statement);
        Assert.Contains("without using them", statement);
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
