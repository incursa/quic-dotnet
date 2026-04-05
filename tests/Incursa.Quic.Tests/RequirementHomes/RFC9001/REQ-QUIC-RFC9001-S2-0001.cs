using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S2-0001">Uppercase BCP 14 keywords in this document MUST be interpreted as described in RFC 2119 and RFC 8174 when they appear in all capitals.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S2-0001")]
public sealed class REQ_QUIC_RFC9001_S2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_UsesAllCapsBCP14Keywords()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9001.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9001-S2-0001");

        Assert.Equal("Interpret uppercase BCP 14 keywords", requirement.GetProperty("title").GetString());
        Assert.Equal(
            "Uppercase BCP 14 keywords in this document MUST be interpreted as described in RFC 2119 and RFC 8174 when they appear in all capitals.",
            requirement.GetProperty("statement").GetString());
        Assert.Contains("MUST", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9001 §2 RFC9001-S2-B2-P1-S1", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
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
