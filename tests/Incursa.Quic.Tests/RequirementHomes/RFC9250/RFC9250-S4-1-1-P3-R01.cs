// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0057")]
public sealed class REQ_QUIC_RFC9250_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqPeerStopSendingTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0007.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0007.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0007.json");

        Assert.Contains("ARC-QUIC-RFC9250-0007", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0007", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0007", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0057", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0057", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0057", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqPeerStopSendingCodeAndTestsAreTraceLinked()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("catch (QuicException exception) when (exception.QuicError is QuicError.StreamAborted or QuicError.OperationAborted)", client, StringComparison.Ordinal);
        Assert.Contains("CloseConnectionAsync(activeConnection, DoqErrorCode.ProtocolError, cancellationToken)", client, StringComparison.Ordinal);
        Assert.Contains("ClientTreatsPeerStopSendingAsFatalProtocolErrorAndClosesConnection", tests, StringComparison.Ordinal);
        Assert.Contains("stream.Abort(QuicAbortDirection.Read, (long)DoqErrorCode.RequestCancelled);", tests, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ peer STOP_SENDING tests.");
    }
}
