using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0007">A description of this summary MUST be included after the table.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0007")]
public sealed class REQ_QUIC_RFC9000_S12P4_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssemblyMap_RecordsTheSection12Point4SummaryDescriptionSentence()
    {
        string repoRoot = GetRepoRoot();
        string assemblyMapPath = Path.Combine(repoRoot, "specs", "generated", "quic", "9000.assembly-map.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(assemblyMapPath));
        JsonElement requirement = document.RootElement
            .GetProperty("final_requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("requirement_id").GetString() == "REQ-QUIC-RFC9000-S12P4-0007");

        Assert.Equal("A description of this summary is included after the table", requirement.GetProperty("title").GetString());
        Assert.Contains("12.4", requirement.GetProperty("source_sections").EnumerateArray().Select(section => section.GetString()));
        Assert.Contains("RFC9000-S12.4-B9-P4-S2", requirement.GetProperty("source_sentence_ids").EnumerateArray().Select(sentenceId => sentenceId.GetString()));
        Assert.Contains(
            "RFC 9000 §12.4 RFC9000-S12.4-B9-P4-S2",
            requirement.GetProperty("source_refs").EnumerateArray().Select(reference => reference.GetString()));
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
