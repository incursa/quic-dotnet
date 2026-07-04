// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0019")]
[Requirement("REQ-QUIC-RFC9250-0020")]
[Requirement("REQ-QUIC-RFC9250-0021")]
[Requirement("REQ-QUIC-RFC9250-0034")]
[Requirement("REQ-QUIC-RFC9250-0035")]
[Requirement("RFC9250-S4-3-1-P1-S1-R02")]
[Requirement("REQ-QUIC-RFC9250-0037")]
[Requirement("REQ-QUIC-RFC9250-0038")]
[Requirement("RFC9250-S4-3-1-P1-S4-R01")]
[Requirement("RFC9250-S4-3-1-P3-R01")]
[Requirement("RFC9250-S4-3-1-P3-S1-R01")]
[Requirement("RFC9250-S4-3-1-P3-S2-R01")]
[Requirement("RFC9250-S4-3-1-P5-S1-R01")]
[Requirement("RFC9250-S4-3-1-P5-S2-R01")]
[Requirement("RFC9250-S4-3-2-P2-S1-R01")]
[Requirement("RFC9250-S4-3-2-P2-S1-R02")]
[Requirement("RFC9250-S4-3-2-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9250_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqCancellationAndResourceLimitTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0003.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0003.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0003.json");

        Assert.Contains("ARC-QUIC-RFC9250-0003", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0003", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0003", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0019", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0034", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-1-P3-R01", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-1-P3-S1-R01", architecture, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-2-P2-S2-R01", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0019", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0034", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-1-P3-R01", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-1-P3-S1-R01", workItem, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-2-P2-S2-R01", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0019", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0034", verification, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-1-P3-R01", verification, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-1-P3-S1-R01", verification, StringComparison.Ordinal);
        Assert.Contains("RFC9250-S4-3-2-P2-S2-R01", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqCancellationAndResourceLimitCodeAndTestsAreTraceLinked()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string options = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServerOptions.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("AbortStreamRead(stream, DoqErrorCode.RequestCancelled)", client, StringComparison.Ordinal);
        Assert.Contains("MaxDanglingStreams", options, StringComparison.Ordinal);
        Assert.Contains("MaxCancellationRequests", options, StringComparison.Ordinal);
        Assert.Contains("CloseConnectionAsync(connection, DoqErrorCode.ExcessiveLoad", server, StringComparison.Ordinal);
        Assert.Contains("AbortStreamWrite(stream, DoqErrorCode.InternalError)", server, StringComparison.Ordinal);
        Assert.Contains("QueryCancellationAbortsReadSideAndLeavesConnectionUsable", tests, StringComparison.Ordinal);
        Assert.Contains("CancellationVolumeLimitClosesConnectionWithExcessiveLoad", tests, StringComparison.Ordinal);
        Assert.Contains("EarlyResetBeforeFinDoesNotDispatchQueryAndLeavesConnectionUsable", tests, StringComparison.Ordinal);
        Assert.Contains("HandlerFailureAbortsStreamWithInternalErrorAndClosesConnection", tests, StringComparison.Ordinal);
        Assert.Contains("DanglingStreamLimitClosesConnectionWithExcessiveLoad", tests, StringComparison.Ordinal);
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9250.json");
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqServerOptions.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ cancellation tests.");
    }
}
