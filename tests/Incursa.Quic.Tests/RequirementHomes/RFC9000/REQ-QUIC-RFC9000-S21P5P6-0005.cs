using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P5P6-0005">Endpoints MAY choose to avoid sending datagrams to these ports or not send datagrams that match these patterns prior to validating the destination address.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S21P5P6-0005")]
public sealed class REQ_QUIC_RFC9000_S21P5P6_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_DescribesPortHygieneGuidance()
    {
        JsonElement requirement = GetRequirement("REQ-QUIC-RFC9000-S21P5P6-0005");

        Assert.Equal("Endpoints MAY choose to avoid sending datagrams to these ports or not send datagrams that match these patterns prior to validating the destination address.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 §21.5.6 RFC9000-S21.5.6-B6-P5-S3", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequirementStatement_DoesNotClaimRuntimeFilteringEnforcement()
    {
        string statement = GetRequirement("REQ-QUIC-RFC9000-S21P5P6-0005").GetProperty("statement").GetString() ?? string.Empty;

        Assert.DoesNotContain("public API", statement);
        Assert.DoesNotContain("runtime enforcement", statement);
        Assert.DoesNotContain("endpoint hardening orchestration", statement);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RequirementStatement_StaysBoundedToPreValidationPortHygiene()
    {
        string statement = GetRequirement("REQ-QUIC-RFC9000-S21P5P6-0005").GetProperty("statement").GetString() ?? string.Empty;

        Assert.Contains("avoid sending datagrams", statement);
        Assert.Contains("these ports", statement);
        Assert.Contains("prior to validating the destination address", statement);
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
