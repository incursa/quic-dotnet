using System.Text;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0027")]
public sealed class REQ_QUIC_INT_0027
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AllImplementationHandshakeMatrixIsTraceLinkedAndManualOnly()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0021.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0021.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0021.json");
        string workflow = ReadRepositoryFile(".github/workflows/interop-runner-handshake.yml");
        string helper = ReadRepositoryFile("scripts/interop/Invoke-QuicInteropRunner.ps1");
        string harness = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/InteropHarnessRunner.cs");
        string readme = ReadRepositoryFile("scripts/interop/README.md");

        Assert.Contains("REQ-QUIC-INT-0027", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-INT-0021", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-INT-0021", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0021", spec, StringComparison.Ordinal);
        Assert.Contains("all-implementation-matrix", workflow, StringComparison.Ordinal);
        Assert.Contains("workflow_dispatch", workflow, StringComparison.Ordinal);
        Assert.Contains("implementations_quic.json", workflow, StringComparison.Ordinal);
        Assert.Contains("role = [string]$property.Value.role", workflow, StringComparison.Ordinal);
        Assert.Contains("image = [string]$property.Value.image", workflow, StringComparison.Ordinal);
        Assert.Contains("local_role = 'client'", workflow, StringComparison.Ordinal);
        Assert.Contains("local_role = 'server'", workflow, StringComparison.Ordinal);
        Assert.Contains("testcases = 'handshake'", workflow, StringComparison.Ordinal);
        Assert.Contains("Upload all-implementation matrix artifacts", workflow, StringComparison.Ordinal);
        Assert.Contains("if: always()", workflow, StringComparison.Ordinal);
        Assert.Contains("Resolve-InteropRunnerPeerImplementationSlots", helper, StringComparison.Ordinal);
        Assert.Contains("PeerImplementationSlots 'all'", helper, StringComparison.Ordinal);
        Assert.Contains("source length unavailable", harness, StringComparison.Ordinal);
        Assert.Contains("CopyHttp09ResponseBodyUntilEndAsync", harness, StringComparison.Ordinal);
        Assert.Contains("local client mode selects every server-capable peer", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("local server mode selects every client-capable peer", readme, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("interop-all-upstream-implementation-handshake-matrix", gapLedger, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0027", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0027", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0027", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AllImplementationHandshakeMatrixDoesNotClaimEveryTestcaseOrUpstreamRegistryParticipation()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0021.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0021.json");
        string workflow = ReadRepositoryFile(".github/workflows/interop-runner-handshake.yml");
        string readme = ReadRepositoryFile("scripts/interop/README.md");

        Assert.Contains("uses the `handshake` testcase only", spec, StringComparison.Ordinal);
        Assert.Contains("outside ordinary push, pull-request, build, test, package, upstream-runner-registry, and support-readiness gates", spec, StringComparison.Ordinal);
        Assert.DoesNotContain("interop-all-upstream-implementation-handshake-matrix", gapLedger, StringComparison.Ordinal);
        Assert.Contains("does not add Incursa.Quic to the upstream registry", readme, StringComparison.Ordinal);
        Assert.Contains("run every testcase", readme, StringComparison.Ordinal);
        Assert.Contains("claim broad support readiness", readme, StringComparison.Ordinal);
        Assert.Contains("Rejected because the request can be satisfied through the existing local replacement-slot model", architecture, StringComparison.Ordinal);
        Assert.Contains("Passing local plan tests or a future hosted handshake matrix does not prove every QUIC testcase", verification, StringComparison.Ordinal);
        Assert.DoesNotContain("testcases = 'handshake,retry,transfer,keyupdate,resumption'", workflow, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientRoleHandshakeCanDownloadWhenTheLocalSourceLengthIsUnavailable()
    {
        byte[] payload = Encoding.UTF8.GetBytes($"all-upstream handshake body {Guid.NewGuid():N}");
        using MemoryStream responseStream = new(payload);
        using MemoryStream destinationStream = new();

        long bytesCopied = await InteropHarnessRunner.CopyHttp09ResponseBodyUntilEndAsync(
            responseStream,
            destinationStream,
            TextWriter.Null,
            "handshake",
            configuredRequestCount: 1,
            requestIndex: 0,
            totalRequestCount: 1,
            requestPath: "/upstream-generated-file",
            responseReadTimeout: Timeout.InfiniteTimeSpan);

        Assert.Equal(payload.Length, bytesCopied);
        Assert.Equal(payload, destinationStream.ToArray());
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

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string gitMarker = Path.Combine(current.FullName, ".git");
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-INT.json");
            string workflowMarker = Path.Combine(current.FullName, ".github", "workflows", "interop-runner-handshake.yml");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(workflowMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the all-implementation handshake matrix requirement home test.");
    }
}
