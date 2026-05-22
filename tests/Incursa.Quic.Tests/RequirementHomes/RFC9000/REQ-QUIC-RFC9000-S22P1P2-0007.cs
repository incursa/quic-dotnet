using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P2-0007">IANA MUST allocate the selected codepoint if the codepoint is unassigned and the requirements of the registration policy are met.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P2-0007")]
public sealed class REQ_QUIC_RFC9000_S22P1P2_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_RequiresAllocationWhenPolicyRequirementsAreMet()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-S22P1P2-0007");

        Assert.Equal("IANA MUST allocate the selected codepoint if the codepoint is unassigned and the requirements...", requirement.GetProperty("title").GetString());
        Assert.Equal("IANA MUST allocate the selected codepoint if the codepoint is unassigned and the requirements of the registration policy are met.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 §22.1.2 RFC9000-S22.1.2-B5-P4-S2", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
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
