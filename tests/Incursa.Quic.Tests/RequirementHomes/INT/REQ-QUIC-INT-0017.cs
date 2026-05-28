// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
        Assert.Contains("- major-peer-matrix", workflow, StringComparison.Ordinal);
        Assert.Contains("- zerortt-server-proof", workflow, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SupportedSubsetMatrixNamesOnlyHelperSupportedRunnerCells()
    {
        string workflow = ReadWorkflow();
        string supportedSubsetJob = ExtractWorkflowSection(
            workflow,
            "  supported-subset:",
            "\n  zerortt-server-proof:");

        Assert.Contains("Run server-handshake-quic-go cell", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("cell: both-retry-quic-go", supportedSubsetJob, StringComparison.Ordinal);
        Assert.Contains("testcases: retry", supportedSubsetJob, StringComparison.Ordinal);
        Assert.Contains("cell: client-transfer-quic-go", supportedSubsetJob, StringComparison.Ordinal);
        Assert.Contains("cell: server-transfer-quic-go", supportedSubsetJob, StringComparison.Ordinal);
        Assert.Contains("testcases: transfer", supportedSubsetJob, StringComparison.Ordinal);
        Assert.Contains("cell: client-multiconnect-quic-go", supportedSubsetJob, StringComparison.Ordinal);
        Assert.Contains("testcases: multiconnect", supportedSubsetJob, StringComparison.Ordinal);
        Assert.DoesNotContain("post-handshake-stream", supportedSubsetJob, StringComparison.Ordinal);
        Assert.DoesNotContain("zerortt", supportedSubsetJob, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("key-update", supportedSubsetJob, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZerorttServerProofProfileIsExplicitAndAdvisory()
    {
        string workflow = ReadWorkflow();
        string zerorttJob = ExtractWorkflowSection(
            workflow,
            "  zerortt-server-proof:",
            "\n  major-peer-matrix:");

        Assert.Contains("coverage_profile == 'zerortt-server-proof'", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("Run server-zerortt-quic-go cell", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("-LocalRole server", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("-ImplementationSlot nginx", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("-PeerImplementationSlots quic-go", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("-TestCases zerortt", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("-RunnerTimeoutSeconds 240", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("-ArtifactsRoot \"${{ github.workspace }}/quic-dotnet/artifacts/interop-runner/server-zerortt-quic-go\"", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("Upload server-zerortt-quic-go artifacts", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("if: always()", zerorttJob, StringComparison.Ordinal);
        Assert.Contains("interop-runner-server-zerortt-quic-go-${{ github.run_id }}", zerorttJob, StringComparison.Ordinal);
        Assert.DoesNotContain("client", zerorttJob, StringComparison.OrdinalIgnoreCase);
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
