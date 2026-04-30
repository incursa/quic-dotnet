namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0017")]
public sealed class REQ_QUIC_INT_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HostedInteropWorkflowExposesManualCoverageProfiles()
    {
        string workflow = ReadWorkflow();

        Assert.Contains("workflow_dispatch:", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("\npush:", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("\npull_request:", workflow, StringComparison.Ordinal);
        Assert.Contains("coverage_profile:", workflow, StringComparison.Ordinal);
        Assert.Contains("default: hosted-handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("- hosted-handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("- supported-subset", workflow, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SupportedSubsetMatrixNamesOnlyHelperSupportedRunnerCells()
    {
        string workflow = ReadWorkflow();

        Assert.Contains("Run server-handshake-quic-go cell", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("cell: both-retry-quic-go", workflow, StringComparison.Ordinal);
        Assert.Contains("testcases: retry", workflow, StringComparison.Ordinal);
        Assert.Contains("cell: client-transfer-quic-go", workflow, StringComparison.Ordinal);
        Assert.Contains("cell: server-transfer-quic-go", workflow, StringComparison.Ordinal);
        Assert.Contains("testcases: transfer", workflow, StringComparison.Ordinal);
        Assert.Contains("cell: client-multiconnect-quic-go", workflow, StringComparison.Ordinal);
        Assert.Contains("testcases: multiconnect", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("post-handshake-stream", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("0-rtt", workflow, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("key-update", workflow, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void WorkflowInvokesRepoLocalHelperWithMatrixValuesAndPerCellArtifacts()
    {
        string workflow = ReadWorkflow();

        Assert.Contains("scripts/interop/Invoke-QuicInteropRunner.ps1", workflow, StringComparison.Ordinal);
        Assert.Contains("-LocalRole server", workflow, StringComparison.Ordinal);
        Assert.Contains("-ImplementationSlot nginx", workflow, StringComparison.Ordinal);
        Assert.Contains("-PeerImplementationSlots quic-go", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("-ArtifactsRoot \"${{ github.workspace }}/quic-dotnet/artifacts/interop-runner/server-handshake-quic-go\"", workflow, StringComparison.Ordinal);
        Assert.Contains("-LocalRole \"${{ matrix.local_role }}\"", workflow, StringComparison.Ordinal);
        Assert.Contains("-ImplementationSlot \"${{ matrix.implementation_slot }}\"", workflow, StringComparison.Ordinal);
        Assert.Contains("-PeerImplementationSlots \"${{ matrix.peer_slots }}\"", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases \"${{ matrix.testcases }}\"", workflow, StringComparison.Ordinal);
        Assert.Contains("-ArtifactsRoot \"${{ github.workspace }}/quic-dotnet/artifacts/interop-runner/${{ matrix.cell }}\"", workflow, StringComparison.Ordinal);
        Assert.Contains("if: always()", workflow, StringComparison.Ordinal);
        Assert.Contains("interop-runner-server-handshake-quic-go-${{ github.run_id }}", workflow, StringComparison.Ordinal);
        Assert.Contains("interop-runner-${{ matrix.cell }}-${{ github.run_id }}", workflow, StringComparison.Ordinal);
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
}
