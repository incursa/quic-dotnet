// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(DoqLoopbackTestCollection.Name)]
public sealed class DoqStreamLifecycleTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0002")]
    [Requirement("REQ-QUIC-RFC9250-0008")]
    [Requirement("REQ-QUIC-RFC9250-0009")]
    [Requirement("REQ-QUIC-RFC9250-0013")]
    [Requirement("REQ-QUIC-RFC9250-0014")]
    [Requirement("REQ-QUIC-RFC9250-0015")]
    [Requirement("REQ-QUIC-RFC9250-0016")]
    [Requirement("REQ-QUIC-RFC9250-0022")]
    [Requirement("REQ-QUIC-RFC9250-0023")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task QueryAsync_UsesOneBidirectionalStreamAndReturnsSameStreamResponse()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x90)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x00)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0x90], result.Response.ToArray());
        DoqQueryContext observed = Assert.Single(handler.Queries);
        Assert.Equal(0, observed.StreamId);
        Assert.Equal([0x00, 0x00, 0x10], observed.Query.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0047")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task QueryAsync_PropagatesServfailResponseCodeFromHandler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static _ =>
            new DoqQueryResult(CreateDnsServfailResponse()));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x0b)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(CreateDnsServfailResponse(), result.Response.ToArray());
        Assert.Equal(0x02, result.Response.Span[3] & 0x0f);
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0011")]
    [Requirement("REQ-QUIC-RFC9250-0012")]
    [Requirement("REQ-QUIC-RFC9250-0017")]
    [Requirement("REQ-QUIC-RFC9250-0099")]
    [Requirement("REQ-QUIC-RFC9250-0100")]
    [Requirement("REQ-QUIC-RFC9250-0101")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConcurrentQueriesUseNextClientInitiatedBidirectionalStreamsOnOneConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CoordinatedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> first = client.QueryAsync(CreateDnsQuery(0x01)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Task<DoqQueryResult> second = client.QueryAsync(CreateDnsQuery(0x02)).AsTask();

        DoqQueryResult[] results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xa1], results[0].Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xa2], results[1].Response.ToArray());
        Assert.Equal([0, 4], handler.StreamIds);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerMayDeferHandlerUntilCompleteLengthPrefixedQueryArrives()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xb0)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await using DoqClient client = DoqClient.Attach(connection);

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x03)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xb0], result.Response.ToArray());
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0009")]
    [Requirement("REQ-QUIC-RFC9250-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ServerRejectsIncompleteDoqQueryFrame()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc0)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] partialQuery = [0x00, 0x03, 0x01];

        await stream.WriteAsync(partialQuery, 0, partialQuery.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await stream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(10));
        QuicException exception = await Assert.ThrowsAsync<QuicException>(async () =>
            await DrainStreamAsync(stream).WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(QuicError.StreamAborted, exception.QuicError);
        Assert.Equal((long)DoqErrorCode.ProtocolError, exception.ApplicationErrorCode);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0052")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ServerTreatsNonZeroQueryMessageIdAsFatalProtocolError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc1)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] encoded = DoqMessageCodec.Encode([0x12, 0x34, 0x10]);

        await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await stream.WriteAsync(encoded, 0, encoded.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await stream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(10));

        QuicException exception = await Assert.ThrowsAsync<QuicException>(async () =>
            await DrainStreamAsync(stream).WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(QuicError.StreamAborted, exception.QuicError);
        Assert.Equal((long)DoqErrorCode.ProtocolError, exception.ApplicationErrorCode);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0052")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientTreatsNonZeroResponseMessageIdAsFatalProtocolError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static _ =>
            new DoqQueryResult(new byte[] { 0x12, 0x34, 0xc2 }));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x0c)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0055")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ServerTreatsMultipleQueriesOnOneStreamAsFatalProtocolError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc3)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] first = DoqMessageCodec.Encode([0x00, 0x00, 0x11]);
        byte[] second = DoqMessageCodec.Encode([0x00, 0x00, 0x12]);

        await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await stream.WriteAsync(first, 0, first.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await stream.WriteAsync(second, 0, second.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await stream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(10));

        QuicException exception = await Assert.ThrowsAsync<QuicException>(async () =>
            await DrainStreamAsync(stream).WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(QuicError.StreamAborted, exception.QuicError);
        Assert.Equal((long)DoqErrorCode.ProtocolError, exception.ApplicationErrorCode);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0042")]
    [Requirement("REQ-QUIC-RFC9250-0034")]
    [Requirement("REQ-QUIC-RFC9250-0035")]
    [Requirement("REQ-QUIC-RFC9250-0036")]
    [Requirement("REQ-QUIC-RFC9250-0037")]
    [Requirement("REQ-QUIC-RFC9250-0038")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task QueryCancellationAbortsReadSideAndLeavesConnectionUsable()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            handler,
            new DoqServerOptions { MaxCancellationRequests = 1 });
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        using CancellationTokenSource queryCancellation = new();

        Task<DoqQueryResult> cancelledQuery = client.QueryAsync(CreateDnsQuery(0x04), queryCancellation.Token).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));

        await queryCancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelledQuery.WaitAsync(TimeSpan.FromSeconds(10)));
        handler.ReleaseFirstQuery();

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x05)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xd5], result.Response.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0042")]
    [Requirement("REQ-QUIC-RFC9250-0043")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task CancellationVolumeLimitClosesConnectionWithExcessiveLoad()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CancellationVolumeDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            handler,
            new DoqServerOptions { MaxCancellationRequests = 1 });
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await using DoqClient client = DoqClient.Attach(connection);

        using CancellationTokenSource firstCancellation = new();
        Task<DoqQueryResult> firstQuery = client.QueryAsync(CreateDnsQuery(0x04), firstCancellation.Token).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));

        await firstCancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstQuery.WaitAsync(TimeSpan.FromSeconds(10)));
        handler.ReleaseFirstQuery();

        using CancellationTokenSource secondCancellation = new();
        Task<DoqQueryResult> secondQuery = client.QueryAsync(CreateDnsQuery(0x05), secondCancellation.Token).AsTask();
        await handler.SecondQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));

        await secondCancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => secondQuery.WaitAsync(TimeSpan.FromSeconds(10)));
        handler.ReleaseSecondQuery();

        QuicException exception = await WaitForConnectionAbortAsync(connection);

        Assert.Equal(QuicError.ConnectionAborted, exception.QuicError);
        Assert.Equal((long)DoqErrorCode.ExcessiveLoad, exception.ApplicationErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0040")]
    [Requirement("REQ-QUIC-RFC9250-0045")]
    [Requirement("REQ-QUIC-RFC9250-0046")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task EarlyResetBeforeFinDoesNotDispatchQueryAndLeavesConnectionUsable()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xe0)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await using DoqClient client = DoqClient.Attach(connection);

        await using (QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10)))
        {
            byte[] partialQuery = [0x00, 0x03, 0x01];
            await stream.WriteAsync(partialQuery, 0, partialQuery.Length).WaitAsync(TimeSpan.FromSeconds(10));
            stream.Abort(QuicAbortDirection.Write, (long)DoqErrorCode.RequestCancelled);
        }

        await WaitForAsync(() => handler.Queries.Length == 0).WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x06)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xe0], result.Response.ToArray());
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0048")]
    [Requirement("REQ-QUIC-RFC9250-0049")]
    [Requirement("REQ-QUIC-RFC9250-0050")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task HandlerFailureAbortsStreamWithInternalErrorAndClosesConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        ThrowOnceDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x07)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0019")]
    [Requirement("REQ-QUIC-RFC9250-0020")]
    [Requirement("REQ-QUIC-RFC9250-0021")]
    [Requirement("REQ-QUIC-RFC9250-0044")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task DanglingStreamLimitClosesConnectionWithExcessiveLoad()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            handler,
            new DoqServerOptions { MaxDanglingStreams = 1 });
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await using DoqClient client = DoqClient.Attach(connection);
        Task<DoqQueryResult> first = client.QueryAsync(CreateDnsQuery(0x09)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> second = client.QueryAsync(CreateDnsQuery(0x0a)).AsTask();

        QuicException exception = await WaitForConnectionAbortAsync(connection);

        Assert.Equal(QuicError.ConnectionAborted, exception.QuicError);
        Assert.Equal((long)DoqErrorCode.ExcessiveLoad, exception.ApplicationErrorCode);

        handler.ReleaseFirstQuery();
        await Assert.ThrowsAsync<QuicException>(() => first.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    private static byte[] CreateDnsQuery(byte idLowByte)
        => [0x12, idLowByte, (byte)(0x10 + idLowByte)];

    private static byte[] CreateDnsResponse(ReadOnlySpan<byte> query, byte responseMarker)
        => [0x00, query.Length > 1 ? query[1] : (byte)0x00, responseMarker];

    private static byte[] CreateDnsServfailResponse()
        => [0x00, 0x00, 0x81, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    private static async Task DrainStreamAsync(QuicStream stream)
    {
        byte[] buffer = new byte[16];
        while (await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false) != 0)
        {
        }
    }

    private static async Task WaitForAsync(Func<bool> predicate)
    {
        TimeSpan pollInterval = TimeSpan.FromMilliseconds(25);
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(2);
        while (!predicate())
        {
            if (DateTimeOffset.UtcNow >= deadline)
            {
                return;
            }

            await Task.Delay(pollInterval).ConfigureAwait(false);
        }
    }

    private static async Task<QuicException> WaitForConnectionAbortAsync(QuicConnection connection)
    {
        TimeSpan pollInterval = TimeSpan.FromMilliseconds(25);
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(10);

        while (true)
        {
            try
            {
                QuicStream stream = await connection
                    .OpenOutboundStreamAsync(QuicStreamType.Bidirectional)
                    .AsTask()
                    .WaitAsync(TimeSpan.FromSeconds(10))
                    .ConfigureAwait(false);

                await stream.DisposeAsync().ConfigureAwait(false);
            }
            catch (QuicException exception) when (exception.QuicError == QuicError.ConnectionAborted)
            {
                return exception;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException("Timed out waiting for the QUIC connection to close after excessive cancellation volume.");
            }

            await Task.Delay(pollInterval).ConfigureAwait(false);
        }
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

    private sealed class CoordinatedDoqHandler : IDoqQueryHandler
    {
        private readonly List<long> streamIds = [];
        private readonly TaskCompletionSource<object?> firstQueryArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<object?> secondQueryArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<object?> FirstQueryArrived => firstQueryArrived;

        public long[] StreamIds
        {
            get
            {
                lock (streamIds)
                {
                    return [.. streamIds];
                }
            }
        }

        public async ValueTask<DoqQueryResult> HandleAsync(DoqQueryContext context, CancellationToken cancellationToken = default)
        {
            bool isFirst;
            lock (streamIds)
            {
                streamIds.Add(context.StreamId);
                isFirst = streamIds.Count == 1;
            }

            if (isFirst)
            {
                firstQueryArrived.TrySetResult(null);
                await secondQueryArrived.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                secondQueryArrived.TrySetResult(null);
            }

            byte marker = context.Query.Span[2] == 0x11 ? (byte)0xa1 : (byte)0xa2;
            return new DoqQueryResult(CreateDnsResponse(context.Query.Span, marker));
        }
    }

    private sealed class DelayedDoqHandler : IDoqQueryHandler
    {
        private readonly TaskCompletionSource<object?> firstQueryArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<object?> releaseFirstQuery = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int queryCount;

        public TaskCompletionSource<object?> FirstQueryArrived => firstQueryArrived;

        public void ReleaseFirstQuery()
            => releaseFirstQuery.TrySetResult(null);

        public async ValueTask<DoqQueryResult> HandleAsync(DoqQueryContext context, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref queryCount) == 1)
            {
                firstQueryArrived.TrySetResult(null);
                await releaseFirstQuery.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            return new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xd5));
        }
    }

    private sealed class CancellationVolumeDoqHandler : IDoqQueryHandler
    {
        private readonly TaskCompletionSource<object?> firstQueryArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<object?> secondQueryArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<object?> releaseFirstQuery = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<object?> releaseSecondQuery = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int queryCount;

        public TaskCompletionSource<object?> FirstQueryArrived => firstQueryArrived;

        public TaskCompletionSource<object?> SecondQueryArrived => secondQueryArrived;

        public void ReleaseFirstQuery()
            => releaseFirstQuery.TrySetResult(null);

        public void ReleaseSecondQuery()
            => releaseSecondQuery.TrySetResult(null);

        public async ValueTask<DoqQueryResult> HandleAsync(DoqQueryContext context, CancellationToken cancellationToken = default)
        {
            int currentQuery = Interlocked.Increment(ref queryCount);
            if (currentQuery == 1)
            {
                firstQueryArrived.TrySetResult(null);
                await releaseFirstQuery.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            else if (currentQuery == 2)
            {
                secondQueryArrived.TrySetResult(null);
                await releaseSecondQuery.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            return new DoqQueryResult(CreateDnsResponse(context.Query.Span, (byte)(0xd5 + currentQuery)));
        }
    }

    private sealed class ThrowOnceDoqHandler : IDoqQueryHandler
    {
        private readonly List<DoqQueryContext> queries = [];
        private int queryCount;

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

            if (Interlocked.Increment(ref queryCount) == 1)
            {
                throw new InvalidOperationException("Simulated DNS handler failure.");
            }

            return ValueTask.FromResult(new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xf8)));
        }
    }

    private sealed class TestServerContext : IAsyncDisposable
    {
        private readonly DoqServer server;
        private readonly CancellationTokenSource cancellation = new();
        private readonly Task serverTask;
        private readonly X509Certificate2 serverCertificate;

        private TestServerContext(DoqServer server, IPEndPoint endpoint, X509Certificate2 serverCertificate)
        {
            this.server = server;
            Endpoint = endpoint;
            this.serverCertificate = serverCertificate;
            serverTask = server.ServeAsync(cancellation.Token);
        }

        public IPEndPoint Endpoint { get; }

        public static async ValueTask<TestServerContext> StartAsync(
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
            return new TestServerContext(server, listenEndPoint, certificate);
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
            await server.DisposeAsync();
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Dispose();
            serverCertificate.Dispose();
        }
    }
}
