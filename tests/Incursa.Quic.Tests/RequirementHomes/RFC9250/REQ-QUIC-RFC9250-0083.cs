// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0083")]
public sealed class REQ_QUIC_RFC9250_0083
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttRefusalTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0013.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0013.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0013.json");

        Assert.Contains("REQ-QUIC-RFC9250-0083", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0083", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0083", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0083", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerUsesRefusedTooEarlyForNonReplayableZeroRtt()
    {
        string defaults = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqDefaults.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("BuildRefusedWithTooEarlyResponse", defaults, StringComparison.Ordinal);
        Assert.Contains("edeTooEarlyOptionCode = 20", defaults, StringComparison.Ordinal);
        Assert.Contains("DnsRefusedRcode", defaults, StringComparison.Ordinal);
        Assert.Contains("BuildRefusedWithTooEarlyResponse(query.Payload.Span)", server, StringComparison.Ordinal);
        Assert.Contains("ServerRefusesNonReplayableZeroRttTransactionWithTooEarlyResponse", tests, StringComparison.Ordinal);
        Assert.Contains("Assert.Equal(5, result.Response.Span[3] & 0x0f)", tests, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerDoesNotApplyTooEarlyBehaviorWithoutZeroRttSignal()
    {
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("IsZeroRtt = options.ZeroRttStreamDetector?.Invoke(connection, stream) ?? false", server, StringComparison.Ordinal);
        Assert.Contains("ServerProcessesNonReplayableTransactionWhenZeroRttSignalIsAbsent", tests, StringComparison.Ordinal);
        Assert.Contains("Assert.Equal([0x00, 0x00, 0x9a], result.Response.ToArray())", tests, StringComparison.Ordinal);
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
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 server 0-RTT refusal tests.");
    }
}
