// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
[Requirement("REQ-QUIC-INT-0030")]
public sealed class REQ_QUIC_INT_0030
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RunnerCellIsTraceLinkedAcrossCanonicalArtifacts()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0024.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0024.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0024.json");
        string runner = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/InteropHarnessRunner.cs");
        string planner = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/InteropHarnessPreflightPlanner.cs");
        string handler = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/InteropHttp3FileHandler.cs");
        string http3Diagnostics = ReadRepositoryFile("src/Incursa.Quic.Http3/IHttp3DiagnosticsSink.cs");
        string http3QlogSink = ReadRepositoryFile("src/Incursa.Quic.Qlog/QuicQlogHttp3DiagnosticsSink.cs");
        string helper = ReadRepositoryFile("scripts/interop/Invoke-QuicInteropRunner.ps1");
        string docs = ReadRepositoryFile("docs/interop-http3-runner.md");

        Assert.Contains("REQ-QUIC-INT-0030", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-INT-0024", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-INT-0024", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0024", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0030", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0030", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0030", verification, StringComparison.Ordinal);
        Assert.Contains("http3-adapter-boundary", gapLedger, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0030", gapLedger, StringComparison.Ordinal);
        Assert.Contains("\"http3\" => RunHttp3ClientAsync", runner, StringComparison.Ordinal);
        Assert.Contains("\"http3\" => RunHttp3ServerAsync", runner, StringComparison.Ordinal);
        Assert.Contains("ApplicationProtocols = [SslApplicationProtocol.Http3]", planner, StringComparison.Ordinal);
        Assert.Contains("InteropHarnessEnvironment.WwwDirectory", planner, StringComparison.Ordinal);
        Assert.Contains("InteropHarnessEnvironment.DownloadsDirectory", planner, StringComparison.Ordinal);
        Assert.Contains("TryGetTransferPathsFromRequestTarget", handler, StringComparison.Ordinal);
        Assert.Contains("DiagnosticsSink = CreateHttp3QlogDiagnosticsSink", runner, StringComparison.Ordinal);
        Assert.Contains("Receives optional HTTP/3 diagnostics", http3Diagnostics, StringComparison.Ordinal);
        Assert.Contains("http3:", http3QlogSink, StringComparison.Ordinal);
        Assert.Contains("QLOGDIR", docs, StringComparison.Ordinal);
        Assert.Contains("SSLKEYLOGFILE", docs, StringComparison.Ordinal);
        Assert.Contains("Wireshark and qvis", docs, StringComparison.Ordinal);
        Assert.Contains("TestCase = 'http3'", helper, StringComparison.Ordinal);
        Assert.Contains("RunnerTestCase = 'http3'", helper, StringComparison.Ordinal);
        Assert.Contains("Classification = 'supported-executed'", helper, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RunnerCellDoesNotPromoteBroaderHttp3Support()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0024.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0024.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0024.json");
        string currentStatus = ReadRepositoryFile("docs/current-status.md");

        Assert.Contains("bounded adapter slice", spec, StringComparison.Ordinal);
        Assert.Contains("broader HTTP/3", spec, StringComparison.Ordinal);
        Assert.Contains("must not be marketed as complete RFC 9114 or RFC 9204 coverage", architecture, StringComparison.Ordinal);
        Assert.Contains("broad all-upstream HTTP/3 peer matrix promotion", workItem, StringComparison.Ordinal);
        Assert.Contains("the 2026-06-16 live local quic-go/quic-go `http3` runner cell", verification, StringComparison.Ordinal);
        Assert.Contains("does not promote broad HTTP/3 production hosting", verification, StringComparison.Ordinal);
        Assert.Contains("broader HTTP/3 production hosting", currentStatus, StringComparison.Ordinal);
        Assert.DoesNotContain("complete RFC 9114 support", spec, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("complete RFC 9204 support", spec, StringComparison.OrdinalIgnoreCase);
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
            string gapMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "REQUIREMENT-GAPS.md");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(gapMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the HTTP/3 interop requirement home test.");
    }
}
