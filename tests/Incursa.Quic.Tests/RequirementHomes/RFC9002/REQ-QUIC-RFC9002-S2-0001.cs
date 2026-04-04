using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S2-0001")]
public sealed class REQ_QUIC_RFC9002_S2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_UsesAllCapsBCP14Keywords()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9002.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9002-S2-0001");

        Assert.Equal("Interpret all-caps BCP 14 keywords", requirement.GetProperty("title").GetString());
        Assert.Equal(
            "The key words in this document MUST be interpreted as described in BCP 14 when, and only when, they appear in all capitals.",
            requirement.GetProperty("statement").GetString());
        Assert.Contains("MUST", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9002 §2 RFC9002-S2-B2-P1-S1", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
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
