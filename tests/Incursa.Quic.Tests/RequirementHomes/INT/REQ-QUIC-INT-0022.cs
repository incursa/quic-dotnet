namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0022")]
public sealed class REQ_QUIC_INT_0022
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionMigrationServerProofProfileAddsDedicatedHostedCorroborationLane()
    {
        string workflow = ReadRepositoryFile(".github/workflows/interop-runner-handshake.yml");
        string helper = ReadRepositoryFile("scripts/interop/Invoke-QuicInteropRunner.ps1");
        string readme = ReadRepositoryFile("scripts/interop/README.md");
        string harnessReadme = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/README.md");
        string currentStatus = ReadRepositoryFile("docs/current-status.md");
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");

        Assert.Contains("coverage_profile == 'connectionmigration-server-proof'", workflow, StringComparison.Ordinal);
        Assert.Contains("coverage_profile == 'connectionmigration-server-proof-blocked'", workflow, StringComparison.Ordinal);
        Assert.Contains("Run connectionmigration proof cell", workflow, StringComparison.Ordinal);
        Assert.Contains("server-connectionmigration-neqo-ngtcp2", workflow, StringComparison.Ordinal);
        Assert.Contains("litespeedtech/lsquic-qir:latest", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("server-connectionmigration-neqo-neqo", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("server-connectionmigration-neqo-lsquic", workflow, StringComparison.Ordinal);
        Assert.Contains("server-connectionmigration-picoquic-blocked", workflow, StringComparison.Ordinal);
        Assert.Contains("privateoctopus/picoquic:latest", workflow, StringComparison.Ordinal);
        Assert.Contains("server-connectionmigration-quiche-blocked", workflow, StringComparison.Ordinal);
        Assert.Contains("cloudflare/quiche-qns:latest", workflow, StringComparison.Ordinal);
        Assert.Contains("server-connectionmigration-lsquic-blocked", workflow, StringComparison.Ordinal);
        Assert.Contains("litespeedtech/lsquic-qir:latest", workflow, StringComparison.Ordinal);
        Assert.Contains("server-connectionmigration-ngtcp2-blocked", workflow, StringComparison.Ordinal);
        Assert.Contains("ghcr.io/ngtcp2/ngtcp2-interop:latest", workflow, StringComparison.Ordinal);
        Assert.Contains("server-connectionmigration-quic-go-blocked", workflow, StringComparison.Ordinal);
        Assert.Contains("server-connectionmigration-msquic-blocked", workflow, StringComparison.Ordinal);
        Assert.Contains("server-connectionmigration-aioquic-blocked", workflow, StringComparison.Ordinal);
        Assert.Contains("aiortc/aioquic-qns:latest", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("server-connectionmigration-neqo-xquic", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases \"${{ matrix.testcases }}\"", workflow, StringComparison.Ordinal);
        Assert.Contains("if: always()", workflow, StringComparison.Ordinal);

        Assert.Contains("TestCase = 'connectionmigration'", helper, StringComparison.Ordinal);
        Assert.Contains("RunnerTestCase = 'connectionmigration'", helper, StringComparison.Ordinal);
        Assert.Contains("Classification = 'supported-executed'", helper, StringComparison.Ordinal);

        Assert.Contains("connectionmigration-server-proof", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration-server-proof-blocked", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("against `ngtcp2`", readme, StringComparison.Ordinal);
        Assert.Contains("picoquic`, `quiche`, `lsquic`, `ngtcp2`, `quic-go`, `msquic`, and `aioquic", readme, StringComparison.Ordinal);
        Assert.Contains("connectionmigration-server-proof", harnessReadme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration-server-proof-blocked", harnessReadme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("against `ngtcp2`", harnessReadme, StringComparison.Ordinal);
        Assert.Contains("picoquic`, `quiche`, `lsquic`, `ngtcp2`, `quic-go`, `msquic`, and `aioquic", harnessReadme, StringComparison.Ordinal);
        Assert.Contains("connectionmigration-server-proof", currentStatus, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration-server-proof-blocked", currentStatus, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("against `ngtcp2`", currentStatus, StringComparison.Ordinal);
        Assert.Contains("preserves `picoquic`,", currentStatus, StringComparison.Ordinal);
        Assert.Contains("`quiche`, `lsquic`, `ngtcp2`, `quic-go`, `msquic`, and `aioquic`", currentStatus, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0022", spec, StringComparison.Ordinal);
        Assert.Contains("connectionmigration-server-proof", spec, StringComparison.Ordinal);
        Assert.Contains("connectionmigration-server-proof-blocked", spec, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("against `ngtcp2`", spec, StringComparison.Ordinal);
        Assert.Contains("picoquic`, `quiche`, `lsquic`, `ngtcp2`, `quic-go`, `msquic`, and `aioquic", spec, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MajorPeerMatrixStillExcludesConnectionMigration()
    {
        string workflow = ReadRepositoryFile(".github/workflows/interop-runner-handshake.yml");
        string majorPeerMatrixJob = ExtractWorkflowSection(
            workflow,
            "  major-peer-matrix:",
            null);

        Assert.DoesNotContain("connectionmigration", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
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

        throw new InvalidOperationException("Unable to locate the repository root for the connectionmigration hosted-proof requirement home test.");
    }
}
