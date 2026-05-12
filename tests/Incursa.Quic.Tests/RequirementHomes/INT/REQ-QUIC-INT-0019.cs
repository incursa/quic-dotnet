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
}
