using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P5-0002">Values between 0x00 and 0x3f inclusive MUST be assigned using Standards Action or IESG Approval.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P5-0002")]
public sealed class REQ_QUIC_RFC9000_S22P5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_UsesStricterPolicyForLowTransportErrorCodepoints()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-S22P5-0002");

        Assert.Equal("Use stricter policy for low transport error codepoints", requirement.GetProperty("title").GetString());
        Assert.Equal(
            "Values between 0x00 and 0x3f inclusive MUST be assigned using Standards Action or IESG Approval.",
            requirement.GetProperty("statement").GetString());
        Assert.Equal(
            "RFC 9000 §22.5 RFC9000-S22.5-B3-P2-S3",
            requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
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
