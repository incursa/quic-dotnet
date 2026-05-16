using System.Linq;
using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0019")]
public sealed class REQ_QUIC_INT_0019
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MajorPeerMatrixProfileCoversGoAndMsquicInClientAndServerRoles()
    {
        string workflow = ReadWorkflow();
        string majorPeerMatrixJob = ExtractWorkflowSection(
            workflow,
            "  major-peer-matrix:",
            null);

        Assert.Contains("coverage_profile == 'major-peer-matrix'", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("fail-fast: false", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("martenseemann/quic-go-interop:latest", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("ghcr.io/microsoft/msquic/qns:main", majorPeerMatrixJob, StringComparison.Ordinal);

        string[] peers = ["quic-go", "msquic"];
        string[] testCases = ["handshake", "retry", "transfer", "keyupdate", "resumption"];
        foreach (string peer in peers)
        {
            foreach (string testCase in testCases)
            {
                Assert.Contains($"cell: client-{testCase}-{peer}", majorPeerMatrixJob, StringComparison.Ordinal);
                Assert.Contains($"cell: server-{testCase}-{peer}", majorPeerMatrixJob, StringComparison.Ordinal);
            }
        }

        Assert.Contains("-LocalRole \"${{ matrix.local_role }}\"", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("-ImplementationSlot \"${{ matrix.implementation_slot }}\"", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("-PeerImplementationSlots \"${{ matrix.peer_slots }}\"", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("-TestCases \"${{ matrix.testcases }}\"", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("-ArtifactsRoot \"${{ github.workspace }}/quic-dotnet/artifacts/interop-runner/${{ matrix.cell }}\"", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("interop-runner-${{ matrix.cell }}-${{ github.run_id }}", majorPeerMatrixJob, StringComparison.Ordinal);
        Assert.Contains("if: always()", majorPeerMatrixJob, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MajorPeerMatrixProfileExcludesBlockedOrOutOfScopeCells()
    {
        string workflow = ReadWorkflow();
        string majorPeerMatrixJob = ExtractWorkflowSection(
            workflow,
            "  major-peer-matrix:",
            null);

        Assert.DoesNotContain("http3", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("zerortt", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("chacha20", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("versionnegotiation", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("v2", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("rebind-port", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("rebind-addr", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connectionmigration", majorPeerMatrixJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("post-handshake-stream", majorPeerMatrixJob, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MajorPeerMatrixInventoryReportMatchesTheWorkflowCellSet()
    {
        string reportJson = ReadRepositoryFile("specs/generated/quic/interop-major-peer-matrix-inventory.json");
        string reportMarkdown = ReadRepositoryFile("specs/generated/quic/interop-major-peer-matrix-inventory.md");

        using JsonDocument reportDocument = JsonDocument.Parse(reportJson);
        JsonElement root = reportDocument.RootElement;
        Assert.Equal("interop-major-peer-matrix-inventory", root.GetProperty("report_id").GetString());
        Assert.True(root.GetProperty("advisory").GetBoolean());
        Assert.Equal("major-peer-matrix", root.GetProperty("source_profile").GetString());
        Assert.Equal(20, root.GetProperty("cell_count").GetInt32());

        JsonElement cells = root.GetProperty("cells");
        Assert.Equal(20, cells.GetArrayLength());

        string[] expectedCellIds =
        [
            "client-handshake-quic-go",
            "server-handshake-quic-go",
            "client-retry-quic-go",
            "server-retry-quic-go",
            "client-transfer-quic-go",
            "server-transfer-quic-go",
            "client-keyupdate-quic-go",
            "server-keyupdate-quic-go",
            "client-resumption-quic-go",
            "server-resumption-quic-go",
            "client-handshake-msquic",
            "server-handshake-msquic",
            "client-retry-msquic",
            "server-retry-msquic",
            "client-transfer-msquic",
            "server-transfer-msquic",
            "client-keyupdate-msquic",
            "server-keyupdate-msquic",
            "client-resumption-msquic",
            "server-resumption-msquic"
        ];

        for (int index = 0; index < expectedCellIds.Length; index++)
        {
            JsonElement cell = cells[index];
            string expectedCellId = expectedCellIds[index];
            string[] expectedCellParts = expectedCellId.Split('-', 3, StringSplitOptions.TrimEntries);

            Assert.Equal(expectedCellId, cell.GetProperty("cell_id").GetString());
            Assert.Equal(expectedCellParts[0], cell.GetProperty("local_role").GetString());
            Assert.Equal(expectedCellParts[2], cell.GetProperty("peer_slot").GetString());
            Assert.Equal(expectedCellParts[1], cell.GetProperty("testcase").GetString());
            Assert.Equal("planned", cell.GetProperty("execution_state").GetString());
            Assert.Equal($"artifacts/interop-runner/{expectedCellId}", cell.GetProperty("target_artifact_root").GetString());
        }
        Assert.Contains("| cell | role | peer | testcase | timeout | execution state | target artifact root |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| client-handshake-quic-go | client | quic-go | handshake | 0 | planned | artifacts/interop-runner/client-handshake-quic-go |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| server-resumption-msquic | server | msquic | resumption | 180 | planned | artifacts/interop-runner/server-resumption-msquic |", reportMarkdown, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MajorPeerMatrixEvidenceReportMatchesTheCompletedHostedRun()
    {
        string reportJson = ReadRepositoryFile("specs/generated/quic/interop-major-peer-matrix-evidence-25904716076.json");
        string reportMarkdown = ReadRepositoryFile("specs/generated/quic/interop-major-peer-matrix-evidence-25904716076.md");

        using JsonDocument reportDocument = JsonDocument.Parse(reportJson);
        JsonElement root = reportDocument.RootElement;
        Assert.Equal("interop-major-peer-matrix-evidence-25904716076", root.GetProperty("report_id").GetString());
        Assert.True(root.GetProperty("advisory").GetBoolean());
        Assert.Equal("major-peer-matrix", root.GetProperty("source_profile").GetString());
        Assert.Equal("REQ-QUIC-INT-0019", root.GetProperty("source_requirement").GetString());
        Assert.Equal(20, root.GetProperty("row_count").GetInt32());
        Assert.Equal(11, root.GetProperty("outcome_counts").GetProperty("passed").GetInt32());
        Assert.Equal(9, root.GetProperty("outcome_counts").GetProperty("failed").GetInt32());

        JsonElement sourceRuns = root.GetProperty("source_runs");
        Assert.Single(sourceRuns.EnumerateArray());
        JsonElement sourceRun = sourceRuns.EnumerateArray().Single();
        Assert.Equal(25904716076, sourceRun.GetProperty("run_id").GetInt64());
        Assert.Equal("major-peer-matrix", sourceRun.GetProperty("bundle").GetString());
        Assert.Equal("artifacts/tmp-major-peer-evidence-25904716076", sourceRun.GetProperty("artifact_root").GetString());

        JsonElement failureClassCounts = root.GetProperty("failure_class_counts");
        Assert.Equal(5, failureClassCounts.GetProperty("peer-tls-alert-50").GetInt32());
        Assert.Equal(1, failureClassCounts.GetProperty("peer-keyupdate-response-timeout").GetInt32());
        Assert.Equal(1, failureClassCounts.GetProperty("peer-transfer-response-timeout").GetInt32());
        Assert.Equal(1, failureClassCounts.GetProperty("peer-keyupdate-missing-file").GetInt32());
        Assert.Equal(1, failureClassCounts.GetProperty("peer-connection-terminated").GetInt32());

        JsonElement rows = root.GetProperty("rows");
        Assert.Equal(20, rows.GetArrayLength());
        AssertEvidenceRow(
            rows,
            "client-handshake-quic-go",
            "quic-go",
            "client",
            "handshake",
            "passed",
            "none",
            "artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-handshake-quic-go-25904716076/20260515-065257862-client-chrome");
        AssertEvidenceRow(
            rows,
            "client-handshake-msquic",
            "msquic",
            "client",
            "handshake",
            "failed",
            "peer-tls-alert-50",
            "artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-handshake-msquic-25904716076/20260515-065520779-client-chrome");
        AssertEvidenceRow(
            rows,
            "client-keyupdate-quic-go",
            "quic-go",
            "client",
            "keyupdate",
            "failed",
            "peer-keyupdate-response-timeout",
            "artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-keyupdate-quic-go-25904716076/20260515-065255258-client-chrome");
        AssertEvidenceRow(
            rows,
            "server-keyupdate-msquic",
            "msquic",
            "server",
            "keyupdate",
            "failed",
            "peer-keyupdate-missing-file",
            "artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-keyupdate-msquic-25904716076/20260515-065307734-server-nginx");
        AssertEvidenceRow(
            rows,
            "server-resumption-msquic",
            "msquic",
            "server",
            "resumption",
            "failed",
            "peer-connection-terminated",
            "artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-resumption-msquic-25904716076/20260515-065254819-server-nginx");

        Assert.Contains("| cell | peer | role | testcase | timeout | outcome class | failure class | artifact root |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| client-handshake-quic-go | quic-go | client | handshake | 0 | passed | none | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-handshake-quic-go-25904716076/20260515-065257862-client-chrome |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| client-handshake-msquic | msquic | client | handshake | 0 | failed | peer-tls-alert-50 | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-handshake-msquic-25904716076/20260515-065520779-client-chrome |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| client-keyupdate-quic-go | quic-go | client | keyupdate | 180 | failed | peer-keyupdate-response-timeout | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-client-keyupdate-quic-go-25904716076/20260515-065255258-client-chrome |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| server-keyupdate-msquic | msquic | server | keyupdate | 180 | failed | peer-keyupdate-missing-file | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-keyupdate-msquic-25904716076/20260515-065307734-server-nginx |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| server-resumption-msquic | msquic | server | resumption | 180 | failed | peer-connection-terminated | artifacts/tmp-major-peer-evidence-25904716076/interop-runner-server-resumption-msquic-25904716076/20260515-065254819-server-nginx |", reportMarkdown, StringComparison.Ordinal);
    }

    private static string ReadWorkflow()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string candidate = Path.Combine(current.FullName, ".github", "workflows", "interop-runner-handshake.yml");
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate .github/workflows/interop-runner-handshake.yml.");
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

    private static void AssertEvidenceRow(
        JsonElement rows,
        string cellId,
        string peerSlot,
        string localRole,
        string testCase,
        string outcomeClass,
        string failureClass,
        string artifactRoot)
    {
        JsonElement row = rows.EnumerateArray().Single(candidate => candidate.GetProperty("cell_id").GetString() == cellId);

        Assert.Equal(cellId, row.GetProperty("cell_id").GetString());
        Assert.Equal(peerSlot, row.GetProperty("peer_slot").GetString());
        Assert.Equal(localRole, row.GetProperty("local_role").GetString());
        Assert.Equal(testCase, row.GetProperty("testcase").GetString());
        Assert.Equal(outcomeClass, row.GetProperty("outcome_class").GetString());
        Assert.Equal(failureClass, row.GetProperty("failure_class").GetString());
        Assert.Equal(artifactRoot, row.GetProperty("artifact_root").GetString());
        Assert.Equal("major-peer-matrix", row.GetProperty("source_bundle").GetString());
        Assert.Equal(25904716076, row.GetProperty("source_run_id").GetInt64());
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

        throw new InvalidOperationException("Unable to locate the repository root.");
    }
}
