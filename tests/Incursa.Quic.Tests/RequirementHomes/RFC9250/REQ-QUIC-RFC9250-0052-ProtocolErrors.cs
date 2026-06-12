// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9250_0052_ProtocolErrors
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0052")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NonZeroMessageIdIsFatalProtocolError()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("contained a non-zero DNS Message ID", client, StringComparison.Ordinal);
        Assert.Contains("contained a non-zero DNS Message ID", server, StringComparison.Ordinal);
        Assert.Contains("ServerTreatsNonZeroQueryMessageIdAsFatalProtocolError", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("ClientTreatsNonZeroResponseMessageIdAsFatalProtocolError", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0052")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroMessageIdIsAcceptedByNormalQueryResponseFlow()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("ClientSendsZeroDnsMessageIdOnDoqQueryStream", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("QueryAsync_UsesOneBidirectionalStreamAndReturnsSameStreamResponse", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0053")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IncompleteLengthPrefixedMessageIsFatalProtocolError()
    {
        DoqException exception = Assert.Throws<DoqException>(() =>
            DoqMessageCodec.Decode([0x00, 0x03, 0x01], out _));

        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        Assert.Contains("incomplete", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ServerRejectsIncompleteDoqQueryFrame", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0053")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CompleteLengthPrefixedMessageDecodes()
    {
        byte[] encoded = DoqMessageCodec.Encode([0x00, 0x00, 0x53]);

        DoqMessage message = DoqMessageCodec.Decode(encoded, out int bytesConsumed);

        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal([0x00, 0x00, 0x53], message.Payload.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0054")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EarlyServerResponseFinIsFatalProtocolError()
    {
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("ClientTreatsEarlyServerResponseFinAsFatalProtocolErrorAndClosesConnection", fatalTests, StringComparison.Ordinal);
        Assert.Contains("encodedResponse.Length - 1", fatalTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0054")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CompleteServerResponseFinIsAccepted()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("QueryAsync_UsesOneBidirectionalStreamAndReturnsSameStreamResponse", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("ServerWritesResponseOnTheSameQueryStream", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0055")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MultipleQueriesOnOneStreamAreFatalProtocolError()
    {
        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("The DoQ stream contained more than one DNS message.", stream, StringComparison.Ordinal);
        Assert.Contains("ServerTreatsMultipleQueriesOnOneStreamAsFatalProtocolError", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0055")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SingleQueryOnOneStreamIsAccepted()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("QueryAsync_UsesOneBidirectionalStreamAndReturnsSameStreamResponse", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("SequentialQueryResponseTransactionsUseSeparateStreams", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0056")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExtraServerResponseOnOneStreamIsFatalProtocolError()
    {
        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("trailing bytes after the DNS message", stream, StringComparison.Ordinal);
        Assert.Contains("ClientTreatsExtraServerResponseBytesAsFatalProtocolErrorAndClosesConnection", fatalTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0056")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SingleServerResponseOnOneStreamIsAccepted()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("QueryAsync_UsesOneBidirectionalStreamAndReturnsSameStreamResponse", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("ConcurrentQueriesWithZeroMessageIdsAreCorrelatedByTheirStreams", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0058")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MissingStreamFinAfterResponseIsFatalProtocolError()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("did not signal STREAM FIN", client, StringComparison.Ordinal);
        Assert.Contains("ClientTreatsMissingStreamFinAfterResponseAsFatalProtocolErrorWithConfiguredTimeout", fatalTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0058")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResponseWithStreamFinIsAccepted()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("ServerWritesResponseOnTheSameQueryStream", lifecycleTests, StringComparison.Ordinal);
        Assert.Contains("stream.CompleteWritesAsync", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0059")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EdnsTcpKeepaliveOptionIsFatalProtocolError()
    {
        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("edns-tcp-keepalive", stream, StringComparison.Ordinal);
        Assert.Contains("ClientRejectsEdnsTcpKeepaliveInResponseAsFatalProtocolError", fatalTests, StringComparison.Ordinal);
        Assert.Contains("ContainsTcpKeepaliveEdnsOption_DetectsKeepaliveOption", fatalTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0059")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MessagesWithoutEdnsTcpKeepaliveAreAcceptedByDetector()
    {
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("ContainsTcpKeepaliveEdnsOption_AllowsMessagesWithoutKeepaliveOption", fatalTests, StringComparison.Ordinal);
        Assert.Contains("BuildDnsMessageWithoutEdns", fatalTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0060")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InboundUnidirectionalStreamIsFatalProtocolError()
    {
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("stream.Type != QuicStreamType.Bidirectional", server, StringComparison.Ordinal);
        Assert.Contains("ServerTreatsInboundUnidirectionalStreamAsFatalProtocolErrorAndClosesConnection", fatalTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0060")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientInitiatedBidirectionalStreamIsAccepted()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        Assert.Contains("OpenOutboundStreamAsync(QuicStreamType.Bidirectional", client, StringComparison.Ordinal);
        Assert.Contains("AcceptInboundStreamAsync", server, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0061")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerInitiatedBidirectionalStreamIsFatalProtocolError()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");

        Assert.Contains("StartInboundStreamMonitor", client, StringComparison.Ordinal);
        Assert.Contains("CloseConnectionAsync(monitoredConnection, DoqErrorCode.ProtocolError", client, StringComparison.Ordinal);
        Assert.Contains("ClientMonitorDetectsInboundStreamFromServerAndClosesConnectionWithProtocolError", fatalTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientOpenedBidirectionalStreamRemainsNormalPath()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("OpenOutboundStreamAsync(QuicStreamType.Bidirectional", client, StringComparison.Ordinal);
        Assert.Contains("QueryAsync_UsesOneBidirectionalStreamAndReturnsSameStreamResponse", lifecycleTests, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0062")]
    [Requirement("REQ-QUIC-RFC9250-0063")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FatalProtocolErrorsCloseConnectionWithProtocolError()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        Assert.Contains("CloseConnectionAsync(activeConnection, DoqErrorCode.ProtocolError", client, StringComparison.Ordinal);
        Assert.Contains("CloseConnectionAsync(connection, DoqErrorCode.ProtocolError", server, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0062")]
    [Requirement("REQ-QUIC-RFC9250-0063")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NonProtocolCloseDoesNotUseProtocolError()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("CloseAsync((long)DoqErrorCode.NoError", client, StringComparison.Ordinal);
        Assert.Contains("Assert.Equal((ulong)DoqErrorCode.NoError", lifecycleTests, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ protocol-error tests.");
    }
}
