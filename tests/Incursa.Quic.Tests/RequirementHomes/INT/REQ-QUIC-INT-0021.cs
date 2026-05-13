namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0021")]
public sealed class REQ_QUIC_INT_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZerorttServerProofProfileIsExplicitAndAdvisory()
    {
        string workflow = ReadRepositoryFile(".github/workflows/interop-runner-handshake.yml");
        string helper = ReadRepositoryFile("scripts/interop/Invoke-QuicInteropRunner.ps1");
        string readme = ReadRepositoryFile("scripts/interop/README.md");

        Assert.Contains("coverage_profile == 'zerortt-server-proof'", workflow, StringComparison.Ordinal);
        Assert.Contains("Run server-zerortt-quic-go cell", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases zerortt", workflow, StringComparison.Ordinal);
        Assert.Contains("-ArtifactsRoot \"${{ github.workspace }}/quic-dotnet/artifacts/interop-runner/server-zerortt-quic-go\"", workflow, StringComparison.Ordinal);
        Assert.Contains("if: always()", workflow, StringComparison.Ordinal);
        Assert.Contains("TestCase = 'zerortt'", helper, StringComparison.Ordinal);
        Assert.Contains("RunnerTestCase = 'zerortt'", helper, StringComparison.Ordinal);
        Assert.Contains("Classification = 'prerequisite-blocked'", helper, StringComparison.Ordinal);
        Assert.Contains("full hosted/Linux zerortt runner success", helper, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("hosted Linux", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("still required before inventory promotion", readme, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MajorPeerMatrixStillExcludesZerortt()
    {
        string workflow = ReadRepositoryFile(".github/workflows/interop-runner-handshake.yml");
        string majorPeerMatrixJob = ExtractWorkflowSection(
            workflow,
            "  major-peer-matrix:",
            null);

        Assert.DoesNotContain("zerortt", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("handshake", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("resumption", majorPeerMatrixJob, StringComparison.Ordinal);
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        string repoRoot = FindRepoRoot();
        string candidate = Path.Combine(repoRoot, relativePath);
        if (File.Exists(candidate))
        {
            return File.ReadAllText(candidate);
        }

        throw new InvalidOperationException($"Unable to locate '{relativePath}' under '{repoRoot}'.");
    }

    private static string ExtractWorkflowSection(
        string workflow,
        string startMarker,
        string? endMarker)
    {
        int startIndex = workflow.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.True(startIndex >= 0, $"Unable to find workflow section start marker '{startMarker}'.");

        int endIndex = endMarker is null
            ? workflow.Length
            : workflow.IndexOf(endMarker, startIndex + startMarker.Length, StringComparison.Ordinal);
        Assert.True(endIndex > startIndex, $"Unable to find workflow section end marker '{endMarker}'.");

        return workflow[startIndex..endIndex];
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string gitMarker = Path.Combine(current.FullName, ".git");
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-INT.json");
            string helperMarker = Path.Combine(current.FullName, "scripts", "interop", "Invoke-QuicInteropRunner.ps1");
            if (Directory.Exists(gitMarker) && File.Exists(specMarker) && File.Exists(helperMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the zerortt hosted-proof requirement home test.");
    }
}
