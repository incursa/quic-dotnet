// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0082")]
public sealed class REQ_QUIC_RFC9250_0082
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttNonReplayableTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0013.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0013.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0013.json");

        Assert.Contains("REQ-QUIC-RFC9250-0082", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0013", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0082", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0082", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0082", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRefusesNonReplayableZeroRttBeforeHandlerDispatch()
    {
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string options = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServerOptions.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("ZeroRttStreamDetector?.Invoke(connection, stream) ?? false", server, StringComparison.Ordinal);
        Assert.Contains("context.IsZeroRtt && !DoqDefaults.IsReplayableQuery", server, StringComparison.Ordinal);
        Assert.Contains("BuildRefusedWithTooEarlyResponse", server, StringComparison.Ordinal);
        Assert.Contains("public Func<QuicConnection, QuicStream, bool>? ZeroRttStreamDetector", options, StringComparison.Ordinal);
        Assert.Contains("ServerRefusesNonReplayableZeroRttTransactionWithTooEarlyResponse", tests, StringComparison.Ordinal);
        Assert.Contains("Assert.Empty(handler.Queries)", tests, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerProcessesNonReplayableTransactionsWhenZeroRttSignalIsAbsent()
    {
        string options = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServerOptions.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("The current transport surface does not expose early-data state directly", options, StringComparison.Ordinal);
        Assert.Contains("ServerProcessesNonReplayableTransactionWhenZeroRttSignalIsAbsent", tests, StringComparison.Ordinal);
        Assert.Contains("Assert.False(observed.IsZeroRtt)", tests, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 server 0-RTT non-replayable tests.");
    }
}
