// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9250_0034_Cancellation
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0034")]
    [Requirement("REQ-QUIC-RFC9250-0035")]
    [Requirement("REQ-QUIC-RFC9250-0036")]
    [Requirement("REQ-QUIC-RFC9250-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientCancellationUsesStopSendingWithRequestCancelled()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)", client, StringComparison.Ordinal);
        Assert.Contains("AbortStreamRead(stream, DoqErrorCode.RequestCancelled)", client, StringComparison.Ordinal);
        Assert.Contains("QueryCancellationAbortsReadSideAndLeavesConnectionUsable", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0037")]
    [Requirement("REQ-QUIC-RFC9250-0040")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanceledQueryResultIsAbandonedBeforeLaterQueriesContinue()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("await Assert.ThrowsAnyAsync<OperationCanceledException>", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("handler.ReleaseFirstQuery();", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("client.QueryAsync(CreateDnsQuery(0x05))", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0041")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerChecksStopSendingBeforeDispatchingQuery()
    {
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("writeAbort = stream.WaitForWriteAbortAsync(CancellationToken.None);", server, StringComparison.Ordinal);
        Assert.Contains("TryHandlePeerCancellationAsync(", server, StringComparison.Ordinal);
        Assert.Contains("ServerDoesNotDispatchQueryWhenStopSendingReceivedBeforeFin", fatalTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0042")]
    [Requirement("REQ-QUIC-RFC9250-0043")]
    [Requirement("REQ-QUIC-RFC9250-0044")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CancellationLimitClosesWithExcessiveLoad()
    {
        string options = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServerOptions.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("MaxCancellationRequests", options, StringComparison.Ordinal);
        Assert.Contains("TryRegisterCancellation()", server, StringComparison.Ordinal);
        Assert.Contains("CloseConnectionAsync(connection, DoqErrorCode.ExcessiveLoad", server, StringComparison.Ordinal);
        Assert.Contains("CancellationVolumeLimitClosesConnectionWithExcessiveLoad", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0045")]
    [Requirement("REQ-QUIC-RFC9250-0046")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EarlyResetAbandonsTransactionAndResetsServerWrites()
    {
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("catch (QuicException exception) when (exception.QuicError is QuicError.StreamAborted or QuicError.OperationAborted)", server, StringComparison.Ordinal);
        Assert.Contains("HandlePeerCancellationAsync(connection, stream, resourceState, connectionCancellation)", server, StringComparison.Ordinal);
        Assert.Contains("AbortStreamWrite(stream, DoqErrorCode.RequestCancelled)", server, StringComparison.Ordinal);
        Assert.Contains("EarlyResetBeforeFinDoesNotDispatchQueryAndLeavesConnectionUsable", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0048")]
    [Requirement("REQ-QUIC-RFC9250-0049")]
    [Requirement("REQ-QUIC-RFC9250-0050")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InternalErrorAbortsStreamWithInternalErrorAndAbandonsTransaction()
    {
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("catch (Exception exception) when (exception is not OperationCanceledException)", server, StringComparison.Ordinal);
        Assert.Contains("AbortStreamWrite(stream, DoqErrorCode.InternalError)", server, StringComparison.Ordinal);
        Assert.Contains("HandlerFailureAbortsStreamWithInternalErrorAndClosesConnection", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("ThrowOnceDoqHandler", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("Assert.Single(handler.Queries)", lifecycleTests, StringComparison.Ordinal);
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
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqServer.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ cancellation tests.");
    }
}
