using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0016")]
public sealed class REQ_QUIC_INT_0016
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ManualHostedHandshakeWorkflowUsesSeparateCheckoutsAndTheNarrowHelperCell()
    {
        string workflow = ReadWorkflow();

        Assert.Contains("workflow_dispatch:", workflow, StringComparison.Ordinal);
        Assert.Contains("default: hosted-handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("Checkout quic-dotnet", workflow, StringComparison.Ordinal);
        Assert.Contains("path: quic-dotnet", workflow, StringComparison.Ordinal);
        Assert.Contains("Checkout quic-interop-runner", workflow, StringComparison.Ordinal);
        Assert.Contains("repository: quic-interop/quic-interop-runner", workflow, StringComparison.Ordinal);
        Assert.Contains("path: quic-interop-runner", workflow, StringComparison.Ordinal);
        Assert.Contains("-LocalRole server", workflow, StringComparison.Ordinal);
        Assert.Contains("-PeerImplementationSlots quic-go", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("if: always()", workflow, StringComparison.Ordinal);
        Assert.Contains("path: quic-dotnet/artifacts/interop-runner/server-handshake-quic-go/", workflow, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdvisoryPeerCharacterizationMatrixKeepsMixedOutcomeClassesVisible()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-peer-characterization-matrix");
        string handshakeRoot = fixture.CreateSubdirectory("server-handshake-quic-go");
        string connectionMigrationRoot = fixture.CreateSubdirectory("server-connectionmigration-neqo");
        string quicGoRoot = fixture.CreateSubdirectory("server-connectionmigration-quic-go");
        string msquicRoot = fixture.CreateSubdirectory("server-connectionmigration-msquic");

        IReadOnlyList<InteropPeerCharacterizationRow> rows = InteropPeerCharacterizationMatrix.Describe(
            [
                new InteropPeerCharacterizationEvidence(
                    handshakeRoot,
                    "server",
                    "quic-go",
                    "handshake",
                    HelperExitCode: 0,
                    RunnerExitCode: 7,
                    HelperOutput:
                    """
                    Interop runner helper complete.
                      Advisory: completed managed handshake response and clean client/server exits.
                    """,
                    RunnerStdErr:
                    """
                    testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified
                    """),
                new InteropPeerCharacterizationEvidence(
                    connectionMigrationRoot,
                    "server",
                    "neqo",
                    "connectionmigration",
                    HelperExitCode: 1,
                    RunnerExitCode: 1,
                    HelperOutput:
                    """
                    Interop runner helper failed.
                      Reason: the runner exited non-zero after producing the expected outputs.
                      Largest ACKed 257 was never sent.
                    """,
                    RunnerStdErr:
                    """
                    Error: Transport(AckedUnsentPacket)
                    """),
                new InteropPeerCharacterizationEvidence(
                    quicGoRoot,
                    "server",
                    "quic-go",
                    "connectionmigration",
                    HelperExitCode: 1,
                    RunnerExitCode: 1,
                    HelperOutput:
                    """
                    Interop runner helper failed.
                      Reason: the runner exited non-zero after producing the expected outputs.
                      peer retired a connection ID while operating in zero-length destination connection ID mode.
                    """,
                    RunnerStdErr:
                    """
                    The connection terminated.
                    """),
                new InteropPeerCharacterizationEvidence(
                    msquicRoot,
                    "server",
                    "msquic",
                    "connectionmigration",
                    HelperExitCode: 1,
                    RunnerExitCode: 1,
                    HelperOutput:
                    """
                    Interop runner helper failed.
                      Reason: the runner exited non-zero after producing the expected outputs.
                    """,
                    RunnerStdErr:
                    """
                    KeyError: 'Layer does not exist in packet'
                    """)
            ]);

        Assert.Collection(
            rows,
            row =>
            {
                Assert.Equal("quic-go", row.PeerSlot);
                Assert.Equal("server", row.LocalRole);
                Assert.Equal("handshake", row.TestCase);
                Assert.Equal("advisory-success", row.OutcomeClass);
                Assert.Equal("none", row.FailureClass);
                Assert.Equal(handshakeRoot, row.ArtifactRoot);
            },
            row =>
            {
                Assert.Equal("neqo", row.PeerSlot);
                Assert.Equal("server", row.LocalRole);
                Assert.Equal("connectionmigration", row.TestCase);
                Assert.Equal("failed", row.OutcomeClass);
                Assert.Equal("peer-acked-unsent-packet", row.FailureClass);
                Assert.Equal(connectionMigrationRoot, row.ArtifactRoot);
            },
            row =>
            {
                Assert.Equal("quic-go", row.PeerSlot);
                Assert.Equal("server", row.LocalRole);
                Assert.Equal("connectionmigration", row.TestCase);
                Assert.Equal("failed", row.OutcomeClass);
                Assert.Equal("peer-zero-length-dcid-cid-retirement", row.FailureClass);
                Assert.Equal(quicGoRoot, row.ArtifactRoot);
            },
            row =>
            {
                Assert.Equal("msquic", row.PeerSlot);
                Assert.Equal("server", row.LocalRole);
                Assert.Equal("connectionmigration", row.TestCase);
                Assert.Equal("failed", row.OutcomeClass);
                Assert.Equal("peer-packet-layer-missing", row.FailureClass);
                Assert.Equal(msquicRoot, row.ArtifactRoot);
            });

        string markdown = InteropPeerCharacterizationMatrix.RenderMarkdown(rows);
        Assert.Contains("| peer | role | testcase | outcome | failure | artifact root |", markdown, StringComparison.Ordinal);
        Assert.Contains("| neqo | server | connectionmigration | failed | peer-acked-unsent-packet |", markdown, StringComparison.Ordinal);
        Assert.Contains("| quic-go | server | connectionmigration | failed | peer-zero-length-dcid-cid-retirement |", markdown, StringComparison.Ordinal);
        Assert.Contains("| msquic | server | connectionmigration | failed | peer-packet-layer-missing |", markdown, StringComparison.Ordinal);
        Assert.Contains("| quic-go | server | handshake | advisory-success | none |", markdown, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdvisoryPeerCharacterizationMatrixSeedReportMatchesTheCurrentSeedRows()
    {
        string reportJson = ReadRepositoryFile("specs/generated/quic/interop-peer-characterization-matrix-pilot.json");
        string reportMarkdown = ReadRepositoryFile("specs/generated/quic/interop-peer-characterization-matrix-pilot.md");

        IReadOnlyList<InteropPeerCharacterizationRow> expectedRows = InteropPeerCharacterizationMatrix.Describe(
            [
                new InteropPeerCharacterizationEvidence(
                    "artifacts/tmp-run-25891504134/20260514-232809159-server-nginx",
                    "server",
                    "neqo",
                    "connectionmigration",
                    HelperExitCode: 1,
                    RunnerExitCode: 1,
                    HelperOutput:
                    """
                    Interop runner helper failed.
                      Reason: the runner exited non-zero after producing the expected outputs.
                      Largest ACKed 257 was never sent.
                    """,
                    RunnerStdErr:
                    """
                    Error: Transport(AckedUnsentPacket)
                    """),
                new InteropPeerCharacterizationEvidence(
                    "artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-quic-go-blocked-25882671754/20260514-200548260-server-neqo",
                    "server",
                    "quic-go",
                    "connectionmigration",
                    HelperExitCode: 1,
                    RunnerExitCode: 1,
                    HelperOutput:
                    """
                    Interop runner helper failed.
                      Reason: the runner exited non-zero after producing the expected outputs.
                      peer retired a connection ID while operating in zero-length destination connection ID mode.
                    """,
                    RunnerStdErr:
                    """
                    The connection terminated.
                    """),
                new InteropPeerCharacterizationEvidence(
                    "artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-msquic-blocked-25882671754/20260514-200543902-server-neqo",
                    "server",
                    "msquic",
                    "connectionmigration",
                    HelperExitCode: 1,
                    RunnerExitCode: 1,
                    HelperOutput:
                    """
                    Interop runner helper failed.
                      Reason: the runner exited non-zero after producing the expected outputs.
                    """,
                    RunnerStdErr:
                    """
                    KeyError: 'Layer does not exist in packet'
                    """),
                new InteropPeerCharacterizationEvidence(
                    "artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-ngtcp2-blocked-25882671754/20260514-200540179-server-neqo",
                    "server",
                    "ngtcp2",
                    "connectionmigration",
                    HelperExitCode: 1,
                    RunnerExitCode: 1,
                    HelperOutput:
                    """
                    Interop runner helper failed.
                      Reason: the runner exited non-zero after producing the expected outputs.
                      File size of /tmp/quic-interop-runner/client_download_c1sv5p5y/teal-bitter-armadillo doesn't match. Original: 2097152 bytes, downloaded: 10240 bytes.
                    """,
                    RunnerStdErr:
                    """
                    File size of /tmp/quic-interop-runner/client_download_c1sv5p5y/teal-bitter-armadillo doesn't match. Original: 2097152 bytes, downloaded: 10240 bytes.
                    """)
            ]);

        IReadOnlyList<InteropPeerCharacterizationRow> majorPeerRows = ReadMajorPeerEvidenceRows();
        expectedRows = [..expectedRows, ..majorPeerRows];

        using JsonDocument reportDocument = JsonDocument.Parse(reportJson);
        JsonElement root = reportDocument.RootElement;
        Assert.Equal("interop-peer-characterization-matrix-pilot", root.GetProperty("report_id").GetString());
        Assert.True(root.GetProperty("advisory").GetBoolean());
        Assert.Equal(24, root.GetProperty("row_count").GetInt32());

        JsonElement sourceRuns = root.GetProperty("source_runs");
        Assert.Equal(3, sourceRuns.GetArrayLength());
        Assert.Equal("major-peer-matrix", sourceRuns[2].GetProperty("bundle").GetString());

        JsonElement rows = root.GetProperty("rows");
        Assert.Equal(expectedRows.Count, rows.GetArrayLength());
        for (int index = 0; index < expectedRows.Count; index++)
        {
            JsonElement row = rows[index];
            InteropPeerCharacterizationRow expected = expectedRows[index];
            Assert.Equal(expected.PeerSlot, row.GetProperty("peer_slot").GetString());
            Assert.Equal(expected.LocalRole, row.GetProperty("local_role").GetString());
            Assert.Equal(expected.TestCase, row.GetProperty("testcase").GetString());
            Assert.Equal(expected.OutcomeClass, row.GetProperty("outcome_class").GetString());
            Assert.Equal(expected.FailureClass, row.GetProperty("failure_class").GetString());
            Assert.Equal(expected.ArtifactRoot, row.GetProperty("artifact_root").GetString());
        }

        Assert.Contains("| peer | role | testcase | outcome class | failure class | artifact root |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| neqo | server | connectionmigration | failed | peer-acked-unsent-packet | artifacts/tmp-run-25891504134/20260514-232809159-server-nginx |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| quic-go | server | connectionmigration | failed | peer-zero-length-dcid-cid-retirement | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-quic-go-blocked-25882671754/20260514-200548260-server-neqo |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| msquic | server | connectionmigration | failed | peer-packet-layer-missing | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-msquic-blocked-25882671754/20260514-200543902-server-neqo |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| ngtcp2 | server | connectionmigration | failed | peer-transfer-size-mismatch | artifacts/tmp-run-25882671754/interop-runner-server-connectionmigration-ngtcp2-blocked-25882671754/20260514-200540179-server-neqo |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| quic-go | client | transfer | failed | peer-transfer-response-timeout |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| msquic | client | handshake | failed | peer-tls-alert-50 |", reportMarkdown, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdvisoryPeerCharacterizationMatrixClosureIsRecordedInTraceArtifacts()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gaps = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        using JsonDocument architecture = JsonDocument.Parse(ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0016.json"));
        using JsonDocument workItem = JsonDocument.Parse(ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0016.json"));
        using JsonDocument verification = JsonDocument.Parse(ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0016.json"));

        Assert.Equal("implemented", architecture.RootElement.GetProperty("status").GetString());
        Assert.Equal("complete", workItem.RootElement.GetProperty("status").GetString());
        Assert.Equal("passed", verification.RootElement.GetProperty("status").GetString());
        Assert.Contains("ARC-QUIC-INT-0016", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-INT-0016", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0016", spec, StringComparison.Ordinal);
        Assert.DoesNotContain("interop-major-peer-matrix-inventory` remains open", gaps, StringComparison.Ordinal);
        Assert.DoesNotContain("interop-peer-characterization-matrix-pilot` remains open", gaps, StringComparison.Ordinal);
        Assert.Contains("closes the advisory reporting gap", verification.RootElement.GetProperty("status_summary").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AdvisoryPeerCharacterizationMatrixRejectsMissingEvidenceFields()
    {
        Assert.Throws<ArgumentException>(
            () => InteropPeerCharacterizationMatrix.Describe(
                new InteropPeerCharacterizationEvidence(
                    "",
                    "server",
                    "neqo",
                    "connectionmigration",
                    HelperExitCode: 1,
                    RunnerExitCode: 1,
                    HelperOutput: "Interop runner helper failed.",
                    RunnerStdErr: "Error: Transport(AckedUnsentPacket)")));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ManualHostedHandshakeWorkflowDoesNotJoinOrdinaryCiTriggers()
    {
        string workflow = ReadWorkflow();

        Assert.DoesNotContain("\npush:", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("\npull_request:", workflow, StringComparison.Ordinal);
    }

    private static string ReadWorkflow()
    {
        return ReadRepositoryFile(".github/workflows/interop-runner-handshake.yml");
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

    private static IReadOnlyList<InteropPeerCharacterizationRow> ReadMajorPeerEvidenceRows()
    {
        string reportJson = ReadRepositoryFile("specs/generated/quic/interop-major-peer-matrix-evidence-25904716076.json");
        using JsonDocument reportDocument = JsonDocument.Parse(reportJson);
        JsonElement rows = reportDocument.RootElement.GetProperty("rows");

        List<InteropPeerCharacterizationRow> result = new(rows.GetArrayLength());
        foreach (JsonElement row in rows.EnumerateArray())
        {
            result.Add(
                new InteropPeerCharacterizationRow(
                    row.GetProperty("peer_slot").GetString() ?? string.Empty,
                    row.GetProperty("local_role").GetString() ?? string.Empty,
                    row.GetProperty("testcase").GetString() ?? string.Empty,
                    row.GetProperty("outcome_class").GetString() ?? string.Empty,
                    row.GetProperty("failure_class").GetString() ?? string.Empty,
                    row.GetProperty("artifact_root").GetString() ?? string.Empty));
        }

        return result;
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

        throw new InvalidOperationException("Unable to locate the repository root for the peer-characterization matrix requirement-home test.");
    }
}
