// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(DoqLoopbackTestCollection.Name)]
public sealed class DoqFatalProtocolErrorTests
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientTreatsEarlyServerResponseFinAsFatalProtocolErrorAndClosesConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        TaskCompletionSource<object?> clientCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            await using QuicStream stream = await connection
                .AcceptInboundStreamAsync(cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            byte[] encodedResponse = DoqMessageCodec.Encode([0x00, 0x00, 0x71]);
            await stream.WriteAsync(encodedResponse, 0, encodedResponse.Length - 1).WaitAsync(TimeSpan.FromSeconds(10));
            await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await clientCompleted.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x11)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        clientCompleted.TrySetResult(null);

        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            client.QueryAsync(CreateDnsQuery(0x12)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientTreatsExtraServerResponseBytesAsFatalProtocolErrorAndClosesConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        TaskCompletionSource<object?> clientCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            await using QuicStream stream = await connection
                .AcceptInboundStreamAsync(cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            byte[] firstResponse = DoqMessageCodec.Encode([0x00, 0x00, 0x72]);
            byte[] secondResponse = DoqMessageCodec.Encode([0x00, 0x00, 0x73]);
            await stream.WriteAsync(firstResponse, 0, firstResponse.Length).WaitAsync(TimeSpan.FromSeconds(10));
            await stream.WriteAsync(secondResponse, 0, secondResponse.Length).WaitAsync(TimeSpan.FromSeconds(10));
            await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await clientCompleted.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x21)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        clientCompleted.TrySetResult(null);

        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            client.QueryAsync(CreateDnsQuery(0x22)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0057")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientTreatsPeerStopSendingAsFatalProtocolErrorAndClosesConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        TaskCompletionSource<object?> clientCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            await using QuicStream stream = await connection
                .AcceptInboundStreamAsync(cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            stream.Abort(QuicAbortDirection.Read, (long)DoqErrorCode.RequestCancelled);
            await clientCompleted.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x31)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        clientCompleted.TrySetResult(null);

        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            client.QueryAsync(CreateDnsQuery(0x32)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0060")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ServerTreatsInboundUnidirectionalStreamAsFatalProtocolErrorAndClosesConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x90)));
        await using DoqServerContext context = await DoqServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await using DoqClient client = DoqClient.Attach(connection);

        await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await stream.WriteAsync([0x00], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        try
        {
            await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (QuicException closeException) when (closeException.QuicError == QuicError.ConnectionAborted)
        {
            Assert.Equal((long)DoqErrorCode.ProtocolError, closeException.ApplicationErrorCode);
        }
        catch (TimeoutException)
        {
            // The close can surface after the write-complete wait under suite load.
        }

        Exception exception = await Assert.ThrowsAnyAsync<Exception>(() =>
            client.QueryAsync(CreateDnsQuery(0x41)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        QuicException quicException = Assert.IsType<QuicException>(
            exception is DoqException doqException ? doqException.InnerException : exception);
        Assert.Equal(QuicError.ConnectionAborted, quicException.QuicError);
        Assert.Equal((long)DoqErrorCode.ProtocolError, quicException.ApplicationErrorCode);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0058")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientTreatsMissingStreamFinAfterResponseAsFatalProtocolErrorWithConfiguredTimeout()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        TaskCompletionSource<object?> responseSent = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            await using QuicStream stream = await connection
                .AcceptInboundStreamAsync(cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            byte[] encodedResponse = DoqMessageCodec.Encode([0x00, 0x00, 0x81]);
            await stream.WriteAsync(encodedResponse, 0, encodedResponse.Length).WaitAsync(TimeSpan.FromSeconds(10));
            await responseSent.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.StreamFinTimeout = TimeSpan.FromSeconds(2);

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x51)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        responseSent.TrySetResult(null);

        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        Assert.Contains("STREAM FIN", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0059")]
    [Requirement("REQ-QUIC-RFC9250-0103")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientRejectsEdnsTcpKeepaliveInResponseAsFatalProtocolError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        TaskCompletionSource<object?> clientCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            await using QuicStream stream = await connection
                .AcceptInboundStreamAsync(cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            byte[] responseWithKeepalive = BuildDnsMessageWithTcpKeepaliveEdnsOption();
            byte[] encoded = DoqMessageCodec.Encode(responseWithKeepalive);
            await stream.WriteAsync(encoded, 0, encoded.Length).WaitAsync(TimeSpan.FromSeconds(10));
            await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await clientCompleted.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x61)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        clientCompleted.TrySetResult(null);

        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        Assert.Contains("edns-tcp-keepalive", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientMonitorDetectsInboundStreamFromServerAndClosesConnectionWithProtocolError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        TaskCompletionSource<object?> serverStreamOpened = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            await using QuicStream stream = await connection
                .OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            await stream.WriteAsync([0x00], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));
            await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await serverStreamOpened.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        await Task.Delay(TimeSpan.FromSeconds(1));

        Exception exception = await Assert.ThrowsAnyAsync<Exception>(() =>
            client.QueryAsync(CreateDnsQuery(0x72)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        serverStreamOpened.TrySetResult(null);

        Assert.True(exception is ObjectDisposedException or QuicException);
        if (exception is QuicException quicException)
        {
            Assert.Equal(QuicError.ConnectionAborted, quicException.QuicError);
            Assert.Equal((long)DoqErrorCode.ProtocolError, quicException.ApplicationErrorCode);
        }
    }

    [Fact]
    [Requirement("RFC9250-S4-3-4-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NormalizeReceivedErrorCode_MapsUnknownCodesToUnspecifiedError()
    {
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x100));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x9999));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(-1));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(6));
    }

    [Fact]
    [Requirement("RFC9250-S4-3-4-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NormalizeReceivedErrorCode_PassesThroughKnownCodes()
    {
        Assert.Equal(DoqErrorCode.NoError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.NoError));
        Assert.Equal(DoqErrorCode.InternalError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.InternalError));
        Assert.Equal(DoqErrorCode.ProtocolError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ProtocolError));
        Assert.Equal(DoqErrorCode.RequestCancelled, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.RequestCancelled));
        Assert.Equal(DoqErrorCode.ExcessiveLoad, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ExcessiveLoad));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.UnspecifiedError));
        Assert.Equal(DoqErrorCode.ErrorReserved, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ErrorReserved));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0059")]
    [Requirement("REQ-QUIC-RFC9250-0103")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContainsTcpKeepaliveEdnsOption_DetectsKeepaliveOption()
    {
        byte[] dnsWithKeepalive = BuildDnsMessageWithTcpKeepaliveEdnsOption();
        byte[] dnsWithoutKeepalive = BuildDnsMessageWithoutEdns();

        Assert.True(DoqMessageCodec.ContainsTcpKeepaliveEdnsOption(dnsWithKeepalive));
        Assert.False(DoqMessageCodec.ContainsTcpKeepaliveEdnsOption(dnsWithoutKeepalive));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0103")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContainsTcpKeepaliveEdnsOption_AllowsMessagesWithoutKeepaliveOption()
    {
        byte[] dnsWithoutKeepalive = BuildDnsMessageWithoutEdns();

        Assert.False(DoqMessageCodec.ContainsTcpKeepaliveEdnsOption(dnsWithoutKeepalive));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0103")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContainsTcpKeepaliveEdnsOptionRejectsOnlyForbiddenOption()
    {
        foreach ((byte[] message, bool containsKeepalive) in new[]
        {
            (BuildDnsMessageWithoutEdns(), false),
            (BuildDnsMessageWithTcpKeepaliveEdnsOption(), true),
        })
        {
            Assert.Equal(containsKeepalive, DoqMessageCodec.ContainsTcpKeepaliveEdnsOption(message));
        }
    }

    [Fact]
    [Requirement("RFC9250-S4-3-1-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ServerDoesNotDispatchQueryWhenStopSendingReceivedBeforeFin()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x40)));
        await using DoqServerContext serverContext = await DoqServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(serverContext.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] encodedQuery = DoqMessageCodec.Encode(CreateDnsQuery(0x41));
        await stream.WriteAsync(encodedQuery, 0, encodedQuery.Length).WaitAsync(TimeSpan.FromSeconds(10));
        stream.Abort(QuicAbortDirection.Read, (long)DoqErrorCode.RequestCancelled);

        await Task.Delay(TimeSpan.FromSeconds(1));

        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("RFC9250-S4-3-2-P2-S2-R02")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientWithMaxUnsolicitedResets_ToleratesResetsBelowLimit()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        int resetCount = 0;
        TaskCompletionSource<object?> clientDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            for (int i = 0; i < 3; i++)
            {
                await using QuicStream stream = await connection
                    .AcceptInboundStreamAsync(cancellationToken)
                    .AsTask()
                    .WaitAsync(TimeSpan.FromSeconds(10));

                if (Interlocked.Increment(ref resetCount) <= 2)
                {
                    stream.Abort(QuicAbortDirection.Write, (long)DoqErrorCode.InternalError);
                }
                else
                {
                    byte[] encoded = DoqMessageCodec.Encode(CreateDnsResponse([0x00, 0x00, 0x11], 0xa0));
                    await stream.WriteAsync(encoded, 0, encoded.Length).WaitAsync(TimeSpan.FromSeconds(10));
                    await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                }
            }

            await clientDone.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.MaxUnsolicitedResets = 2;

        DoqException firstReset = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x51)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(DoqErrorCode.ProtocolError, firstReset.ErrorCode);

        DoqException secondReset = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x52)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(DoqErrorCode.ProtocolError, secondReset.ErrorCode);

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x53)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal([0x00, 0x00, 0xa0], result.Response.ToArray());

        clientDone.TrySetResult(null);
    }

    [Fact]
    [Requirement("RFC9250-S4-3-2-P2-S2-R02")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientWithMaxUnsolicitedResets_ClosesConnectionWhenLimitExceeded()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        int resetCount = 0;
        TaskCompletionSource<object?> clientDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            try
            {
                for (int i = 0; i < 3; i++)
                {
                    await using QuicStream stream = await connection
                        .AcceptInboundStreamAsync(cancellationToken)
                        .AsTask()
                        .WaitAsync(TimeSpan.FromSeconds(10));

                    stream.Abort(QuicAbortDirection.Write, (long)DoqErrorCode.InternalError);
                    Interlocked.Increment(ref resetCount);
                }
            }
            catch (QuicException) when (Volatile.Read(ref resetCount) >= 2)
            {
                // The client is required to terminate after the reset limit is exceeded.
            }

            await clientDone.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.MaxUnsolicitedResets = 1;

        await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x61)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x62)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        ObjectDisposedException disposed = await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            client.QueryAsync(CreateDnsQuery(0x63)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Contains("Cannot access", disposed.Message, StringComparison.Ordinal);
        Assert.Equal(2, Volatile.Read(ref resetCount));

        clientDone.TrySetResult(null);
    }

    [Fact]
    [Requirement("RFC9250-S4-3-1-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RegisteredErrorCodePathwayIsDocumentedInDoqErrorCode()
    {
        Assert.NotNull(typeof(DoqErrorCodeExtensions).GetMethod(nameof(DoqErrorCodeExtensions.NormalizeReceivedErrorCode)));

        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x100));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x9999));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)6));
    }

    [Fact]
    [Requirement("RFC9250-S4-3-1-P1-S2-R01")]
    [Requirement("RFC9250-S4-3-4-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NormalizeReceivedErrorCodeDistinguishesRegisteredAndUnexpectedValues()
    {
        foreach ((long receivedCode, DoqErrorCode expectedCode) in new[]
        {
            ((long)DoqErrorCode.NoError, DoqErrorCode.NoError),
            ((long)DoqErrorCode.InternalError, DoqErrorCode.InternalError),
            ((long)DoqErrorCode.ProtocolError, DoqErrorCode.ProtocolError),
            ((long)DoqErrorCode.RequestCancelled, DoqErrorCode.RequestCancelled),
            ((long)DoqErrorCode.ExcessiveLoad, DoqErrorCode.ExcessiveLoad),
            ((long)DoqErrorCode.UnspecifiedError, DoqErrorCode.UnspecifiedError),
            ((long)DoqErrorCode.ErrorReserved, DoqErrorCode.ErrorReserved),
            (-1, DoqErrorCode.UnspecifiedError),
            (6, DoqErrorCode.UnspecifiedError),
            (0x100, DoqErrorCode.UnspecifiedError),
            (0x9999, DoqErrorCode.UnspecifiedError),
        })
        {
            Assert.Equal(expectedCode, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(receivedCode));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0075")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ConnectionFailureSurfacesClearExceptionOnSubsequentQuery()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        TaskCompletionSource<object?> clientCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            await using QuicStream stream = await connection
                .AcceptInboundStreamAsync(cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            byte[] encodedResponse = DoqMessageCodec.Encode([0x00, 0x00, 0x81]);
            await stream.WriteAsync(encodedResponse, 0, encodedResponse.Length - 1).WaitAsync(TimeSpan.FromSeconds(10));
            await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await clientCompleted.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqException firstException = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x05)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(DoqErrorCode.ProtocolError, firstException.ErrorCode);

        ObjectDisposedException secondException = await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            client.QueryAsync(CreateDnsQuery(0x06)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Contains("Cannot access", secondException.Message, StringComparison.Ordinal);

        clientCompleted.TrySetResult(null);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0075")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectionFailureAbandonsInProgressQuery()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        TaskCompletionSource<object?> queryReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using RawServerContext context = await RawServerContext.StartAsync(async (connection, cancellationToken) =>
        {
            await using QuicStream stream = await connection
                .AcceptInboundStreamAsync(cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            DoqMessage query = await ReadSingleDoqMessageUntilFinAsync(stream, cancellationToken)
                .WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal([0x00, 0x00, 0x45], query.Payload.ToArray());
            queryReceived.TrySetResult(null);

            await connection
                .CloseAsync((long)DoqErrorCode.InternalError, cancellationToken)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));
        });

        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> queryTask = client.QueryAsync(CreateDnsQuery(0x35)).AsTask();
        await queryReceived.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Exception? exception = await Record.ExceptionAsync(() => queryTask.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.NotNull(exception);
        Assert.False(queryTask.IsCompletedSuccessfully, "The in-progress query must not produce a response after the connection fails.");
        Assert.True(
            queryTask.IsCompleted,
            "The in-progress query must be abandoned rather than left pending. " +
            QuicLoopbackEstablishmentTestSupport.DescribeConnection(client.CurrentConnection));
        Assert.False(exception is TimeoutException, "The in-progress query must fault because of connection failure, not the test timeout.");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0057")]
    [Requirement("REQ-QUIC-RFC9250-0075")]
    [Requirement("RFC9250-S4-3-1-P2-S1-R01")]
    [Requirement("RFC9250-S4-3-2-P2-S2-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LoopbackFatalErrorPoliciesRemainTraceLinked()
    {
        string fatalTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqFatalProtocolErrorTests.cs");
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        foreach ((string source, string expected) in new[]
        {
            (fatalTests, "ClientTreatsPeerStopSendingAsFatalProtocolErrorAndClosesConnection"),
            (fatalTests, "ServerDoesNotDispatchQueryWhenStopSendingReceivedBeforeFin"),
            (fatalTests, "ClientWithMaxUnsolicitedResets_ToleratesResetsBelowLimit"),
            (fatalTests, "ClientWithMaxUnsolicitedResets_ClosesConnectionWhenLimitExceeded"),
            (fatalTests, "ConnectionFailureSurfacesClearExceptionOnSubsequentQuery"),
            (fatalTests, "ConnectionFailureAbandonsInProgressQuery"),
            (client, "MaxUnsolicitedResets"),
            (client, "SignalConnectionFailure"),
            (server, "AbortStreamWrite(stream, DoqErrorCode.RequestCancelled)"),
        })
        {
            Assert.Contains(expected, source, StringComparison.Ordinal);
        }
    }

    private static async Task<DoqMessage> ReadSingleDoqMessageUntilFinAsync(
        QuicStream stream,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[256];
        List<byte> pending = [];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            pending.AddRange(buffer.AsSpan(0, bytesRead).ToArray());
        }

        byte[] source = [.. pending];
        Assert.True(DoqMessageCodec.TryDecode(source, out DoqMessage message, out int bytesConsumed));
        Assert.Equal(source.Length, bytesConsumed);
        return message;
    }

    private static byte[] BuildDnsMessageWithTcpKeepaliveEdnsOption()
    {
        byte[] message = new byte[44];
        message[0] = 0x00; message[1] = 0x00;
        message[2] = 0x01; message[3] = 0x00;
        message[4] = 0x00; message[5] = 0x01;
        message[6] = 0x00; message[7] = 0x00;
        message[8] = 0x00; message[9] = 0x00;
        message[10] = 0x00; message[11] = 0x01;

        int offset = 12;
        message[offset] = 0x07; offset++;
        WriteAscii("example", message, ref offset);
        message[offset] = 0x03; offset++;
        WriteAscii("com", message, ref offset);
        message[offset] = 0x00; offset++;

        message[offset] = 0x00; message[offset + 1] = 0x01;
        message[offset + 2] = 0x00; message[offset + 3] = 0x01;
        offset += 4;

        message[offset] = 0x00; offset++;

        message[offset] = 0x00; message[offset + 1] = 0x29;
        message[offset + 2] = 0x10; message[offset + 3] = 0x00;
        message[offset + 4] = 0x00; message[offset + 5] = 0x00;
        message[offset + 6] = 0x00; message[offset + 7] = 0x00;
        message[offset + 8] = 0x00; message[offset + 9] = 0x04;

        message[offset + 10] = 0x00; message[offset + 11] = 0x0B;
        message[offset + 12] = 0x00; message[offset + 13] = 0x00;

        return message;
    }

    private static byte[] BuildDnsMessageWithoutEdns()
    {
        byte[] message = new byte[29];
        message[0] = 0x00; message[1] = 0x00;
        message[2] = 0x01; message[3] = 0x00;
        message[4] = 0x00; message[5] = 0x01;
        message[6] = 0x00; message[7] = 0x00;
        message[8] = 0x00; message[9] = 0x00;
        message[10] = 0x00; message[11] = 0x00;

        int offset = 12;
        message[offset] = 0x07; offset++;
        WriteAscii("example", message, ref offset);
        message[offset] = 0x03; offset++;
        WriteAscii("com", message, ref offset);
        message[offset] = 0x00; offset++;

        message[offset] = 0x00; message[offset + 1] = 0x01;
        message[offset + 2] = 0x00; message[offset + 3] = 0x01;

        return message;
    }

    private static byte[] CreateDnsQuery(byte idLowByte)
        => [0x12, idLowByte, (byte)(0x10 + idLowByte)];

    private static byte[] CreateDnsResponse(ReadOnlySpan<byte> query, byte responseMarker)
        => [0x00, query.Length > 1 ? query[1] : (byte)0x00, responseMarker];

    private static void WriteAscii(string text, byte[] destination, ref int offset)
    {
        foreach (char c in text)
        {
            destination[offset++] = (byte)c;
        }
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ fatal protocol error tests.");
    }

    private sealed class RecordingDoqHandler : IDoqQueryHandler
    {
        private readonly Func<DoqQueryContext, DoqQueryResult> responseFactory;
        private readonly List<DoqQueryContext> queries = [];

        public RecordingDoqHandler(Func<DoqQueryContext, DoqQueryResult> responseFactory)
        {
            this.responseFactory = responseFactory;
        }

        public DoqQueryContext[] Queries
        {
            get
            {
                lock (queries)
                {
                    return [.. queries];
                }
            }
        }

        public ValueTask<DoqQueryResult> HandleAsync(DoqQueryContext context, CancellationToken cancellationToken = default)
        {
            lock (queries)
            {
                queries.Add(context);
            }

            return ValueTask.FromResult(responseFactory(context));
        }
    }

    private sealed class RawServerContext : IAsyncDisposable
    {
        private readonly QuicListener listener;
        private readonly CancellationTokenSource cancellation = new();
        private readonly Task serverTask;
        private readonly X509Certificate2 serverCertificate;

        private RawServerContext(
            QuicListener listener,
            IPEndPoint endpoint,
            X509Certificate2 serverCertificate,
            Func<QuicConnection, CancellationToken, Task> serverBody)
        {
            this.listener = listener;
            Endpoint = endpoint;
            this.serverCertificate = serverCertificate;
            serverTask = RunServerAsync(serverBody);
        }

        public IPEndPoint Endpoint { get; }

        public static async ValueTask<RawServerContext> StartAsync(Func<QuicConnection, CancellationToken, Task> serverBody)
        {
            X509Certificate2 certificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(certificate);
            serverOptions.ServerAuthenticationOptions.ApplicationProtocols = [DoqDefaults.ApplicationProtocol];
            serverOptions.MaxInboundBidirectionalStreams = 8;

            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = listenEndPoint,
                ApplicationProtocols = [DoqDefaults.ApplicationProtocol],
                ListenBacklog = 1,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
            };

            QuicListener listener = await QuicListener.ListenAsync(listenerOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            return new RawServerContext(listener, listenEndPoint, certificate, serverBody);
        }

        public QuicClientConnectionOptions CreateClientOptions()
        {
            QuicClientConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                new IPEndPoint(IPAddress.Loopback, Endpoint.Port),
                targetHost: "localhost",
                trustedServerCertificate: serverCertificate);
            options.ClientAuthenticationOptions.ApplicationProtocols = [DoqDefaults.ApplicationProtocol];
            options.MaxInboundBidirectionalStreams = 8;
            return options;
        }

        private async Task RunServerAsync(Func<QuicConnection, CancellationToken, Task> serverBody)
        {
            try
            {
                await using QuicConnection connection = await listener
                    .AcceptConnectionAsync(cancellation.Token)
                    .AsTask()
                    .WaitAsync(TimeSpan.FromSeconds(10));

                await using (connection.ConfigureAwait(false))
                {
                    await serverBody(connection, cancellation.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException) when (cancellation.IsCancellationRequested)
            {
            }
        }

        public async ValueTask DisposeAsync()
        {
            cancellation.Cancel();
            await listener.DisposeAsync().ConfigureAwait(false);
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Dispose();
            serverCertificate.Dispose();
        }
    }

    private sealed class DoqServerContext : IAsyncDisposable
    {
        private readonly DoqServer server;
        private readonly CancellationTokenSource cancellation = new();
        private readonly Task serverTask;
        private readonly X509Certificate2 serverCertificate;

        private DoqServerContext(DoqServer server, IPEndPoint endpoint, X509Certificate2 serverCertificate)
        {
            this.server = server;
            Endpoint = endpoint;
            this.serverCertificate = serverCertificate;
            serverTask = server.ServeAsync(cancellation.Token);
        }

        public IPEndPoint Endpoint { get; }

        public static async ValueTask<DoqServerContext> StartAsync(
            IDoqQueryHandler handler,
            DoqServerOptions? doqServerOptions = null)
        {
            X509Certificate2 certificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(certificate);
            serverOptions.ServerAuthenticationOptions.ApplicationProtocols = [DoqDefaults.ApplicationProtocol];
            serverOptions.MaxInboundBidirectionalStreams = 8;

            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = listenEndPoint,
                ApplicationProtocols = [DoqDefaults.ApplicationProtocol],
                ListenBacklog = 1,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
            };

            DoqServer server = await DoqServer
                .ListenAsync(listenerOptions, handler, doqServerOptions)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));
            return new DoqServerContext(server, listenEndPoint, certificate);
        }

        public QuicClientConnectionOptions CreateClientOptions()
        {
            QuicClientConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                new IPEndPoint(IPAddress.Loopback, Endpoint.Port),
                targetHost: "localhost",
                trustedServerCertificate: serverCertificate);
            options.ClientAuthenticationOptions.ApplicationProtocols = [DoqDefaults.ApplicationProtocol];
            options.MaxInboundBidirectionalStreams = 8;
            return options;
        }

        public async ValueTask DisposeAsync()
        {
            cancellation.Cancel();
            await server.DisposeAsync().ConfigureAwait(false);
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Dispose();
            serverCertificate.Dispose();
        }
    }
}
