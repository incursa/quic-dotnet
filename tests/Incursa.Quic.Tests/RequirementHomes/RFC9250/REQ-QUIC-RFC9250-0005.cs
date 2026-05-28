// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0054")]
[Requirement("REQ-QUIC-RFC9250-0056")]
[Requirement("REQ-QUIC-RFC9250-0060")]
[Requirement("REQ-QUIC-RFC9250-0062")]
[Requirement("REQ-QUIC-RFC9250-0063")]
public sealed class REQ_QUIC_RFC9250_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqFatalProtocolErrorTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0005.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0005.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0005.json");

        Assert.Contains("ARC-QUIC-RFC9250-0005", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0005", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0005", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0054", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0056", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0060", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0062", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0063", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0054", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0056", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0060", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0062", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0063", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0054", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0056", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0060", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0062", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0063", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqFatalProtocolErrorCodeAndTestsAreTraceLinked()
    {
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("if (stream.Type != QuicStreamType.Bidirectional)", server, StringComparison.Ordinal);
        Assert.Contains("CloseConnectionAsync(connection, DoqErrorCode.ProtocolError, CancellationToken.None)", server, StringComparison.Ordinal);
        Assert.Contains("The DoQ stream contained more than one DNS message.", stream, StringComparison.Ordinal);
        Assert.Contains("The DoQ stream contained trailing bytes after the DNS message.", stream, StringComparison.Ordinal);
        Assert.Contains("ClientTreatsEarlyServerResponseFinAsFatalProtocolErrorAndClosesConnection", tests, StringComparison.Ordinal);
        Assert.Contains("ClientTreatsExtraServerResponseBytesAsFatalProtocolErrorAndClosesConnection", tests, StringComparison.Ordinal);
        Assert.Contains("ServerTreatsInboundUnidirectionalStreamAsFatalProtocolErrorAndClosesConnection", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqStream.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ fatal protocol-error tests.");
    }
}
