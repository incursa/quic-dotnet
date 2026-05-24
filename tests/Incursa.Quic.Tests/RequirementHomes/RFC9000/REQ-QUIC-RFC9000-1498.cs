using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1498">A request to remove a codepoint MUST be reviewed by the designated experts.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1498")]
public sealed class REQ_QUIC_RFC9000_1498
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_UsesDesignatedExpertReviewForCodepointRemovalRequests()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-1498");

        Assert.Equal("Review codepoint removal requests", requirement.GetProperty("title").GetString());
        Assert.Equal("A request to remove a codepoint MUST be reviewed by the designated experts.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 section 22.1.3 RFC9000-S22P1P3-B2-P2-S1", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1498")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotTreatReviewAsRemovalAuthorization()
    {
        JsonElement requirement = LoadRequirement();
        string statement = requirement.GetProperty("statement").GetString()!;

        Assert.Contains("MUST be reviewed", statement);
        Assert.DoesNotContain("MAY be removed", statement);
        Assert.DoesNotContain("MUST be removed", statement);
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
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-1498")
            .Clone();
    }
}
