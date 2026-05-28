// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0002")]
[Requirement("REQ-QUIC-RFC9250-0008")]
[Requirement("REQ-QUIC-RFC9250-0009")]
[Requirement("REQ-QUIC-RFC9250-0011")]
[Requirement("REQ-QUIC-RFC9250-0012")]
[Requirement("REQ-QUIC-RFC9250-0013")]
[Requirement("REQ-QUIC-RFC9250-0014")]
[Requirement("REQ-QUIC-RFC9250-0015")]
[Requirement("REQ-QUIC-RFC9250-0016")]
[Requirement("REQ-QUIC-RFC9250-0017")]
[Requirement("REQ-QUIC-RFC9250-0018")]
[Requirement("REQ-QUIC-RFC9250-0022")]
[Requirement("REQ-QUIC-RFC9250-0023")]
[Requirement("REQ-QUIC-RFC9250-0099")]
[Requirement("REQ-QUIC-RFC9250-0100")]
[Requirement("REQ-QUIC-RFC9250-0101")]
public sealed class REQ_QUIC_RFC9250_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqStreamLifecycleTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0002.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0002.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0002.json");

        Assert.Contains("ARC-QUIC-RFC9250-0002", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0002", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0002", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0002", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0017", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0101", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0002", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0017", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0101", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0002", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0017", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0101", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqStreamLifecycleCodeAndTestsAreTraceLinked()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string handler = ReadRepositoryFile("src/Incursa.Quic.Dns/IDoqQueryHandler.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("OpenOutboundStreamAsync(QuicStreamType.Bidirectional", client, StringComparison.Ordinal);
        Assert.Contains("WriteMessageAndCompleteAsync", client, StringComparison.Ordinal);
        Assert.Contains("AcceptInboundStreamAsync", server, StringComparison.Ordinal);
        Assert.Contains("HandleQueryStreamAsync", server, StringComparison.Ordinal);
        Assert.Contains("IDoqQueryHandler", handler, StringComparison.Ordinal);
        Assert.Contains("QueryAsync_UsesOneBidirectionalStreamAndReturnsSameStreamResponse", tests, StringComparison.Ordinal);
        Assert.Contains("ConcurrentQueriesUseNextClientInitiatedBidirectionalStreamsOnOneConnection", tests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqClient.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ stream lifecycle tests.");
    }
}
