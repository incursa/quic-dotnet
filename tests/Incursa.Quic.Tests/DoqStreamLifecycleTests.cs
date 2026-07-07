// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(DoqLoopbackTestCollection.Name)]
public sealed class DoqStreamLifecycleTests
{
    private const ushort DnsQTypeIxfr = 251;
    private const ushort DnsQTypeAxfr = 252;
    private const int LargeDnsResponseLength = 2048;

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0002")]
    [Requirement("REQ-QUIC-RFC9250-0008")]
    [Requirement("REQ-QUIC-RFC9250-0009")]
    [Requirement("RFC9250-S4-2-P6-S1-R01")]
    [Requirement("RFC9250-S4-2-P6-S1-R02")]
    [Requirement("RFC9250-S4-2-P7-R01")]
    [Requirement("RFC9250-S4-2-P7-R02")]
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
    [Requirement("REQ-QUIC-RFC9250-0022")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientSendsZeroDnsMessageIdOnDoqQueryStream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x91)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(new byte[] { 0x00, 0x00, 0x31 }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0x91], result.Response.ToArray());
        DoqQueryContext observed = Assert.Single(handler.Queries);
        Assert.Equal([0x00, 0x00, 0x31], observed.Query.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0022")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientNormalizesNonZeroDnsMessageIdBeforeSendingDoqQuery()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x92)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(new byte[] { 0x12, 0x34, 0x32 }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0x92], result.Response.ToArray());
        DoqQueryContext observed = Assert.Single(handler.Queries);
        Assert.Equal([0x00, 0x00, 0x32], observed.Query.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0023")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConcurrentQueriesWithZeroMessageIdsAreCorrelatedByTheirStreams()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CoordinatedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> first = client.QueryAsync(new byte[] { 0x00, 0x00, 0x11 }).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Task<DoqQueryResult> second = client.QueryAsync(new byte[] { 0x00, 0x00, 0x12 }).AsTask();

        DoqQueryResult[] results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xa1], results[0].Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xa2], results[1].Response.ToArray());
        long[] streamIds = handler.StreamIds;
        Assert.Equal(2, streamIds.Length);
        Assert.NotEqual(streamIds[0], streamIds[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0023")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ConcurrentQueriesWithSameNonZeroMessageIdAreCorrelatedByTheirStreams()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CoordinatedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> first = client.QueryAsync(new byte[] { 0x44, 0x44, 0x11 }).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Task<DoqQueryResult> second = client.QueryAsync(new byte[] { 0x44, 0x44, 0x12 }).AsTask();

        DoqQueryResult[] results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xa1], results[0].Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xa2], results[1].Response.ToArray());
        long[] streamIds = handler.StreamIds;
        Assert.Equal(2, streamIds.Length);
        Assert.NotEqual(streamIds[0], streamIds[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0002")]
    [Requirement("REQ-QUIC-RFC9250-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SequentialQueryResponseTransactionsUseSeparateStreams()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
        {
            byte marker = context.Query.Span[2] == 0x61 ? (byte)0xb1 : (byte)0xb2;
            return new DoqQueryResult(CreateDnsResponse(context.Query.Span, marker));
        });
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult first = await client.QueryAsync(new byte[] { 0x00, 0x00, 0x61 }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        DoqQueryResult second = await client.QueryAsync(new byte[] { 0x00, 0x00, 0x62 }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xb1], first.Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xb2], second.Response.ToArray());
        DoqQueryContext[] queries = handler.Queries;
        Assert.Equal(2, queries.Length);
        Assert.NotEqual(queries[0].StreamId, queries[1].StreamId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0002")]
    [Requirement("REQ-QUIC-RFC9250-0008")]
    [Requirement("REQ-QUIC-RFC9250-0017")]
    [Requirement("REQ-QUIC-RFC9250-0023")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public Task VariedDnsMessageIdsUseSeparateClientStreamsRegardlessOfDnsId()
    {
        return AssertVariedDnsMessageIdsUseSeparateStreamsWithZeroedDoqIds();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0009")]
    [Requirement("REQ-QUIC-RFC9250-0022")]
    [Requirement("RFC9250-S4-2-P6-S1-R01")]
    [Requirement("RFC9250-S4-2-P7-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public Task VariedDnsMessageIdsPreserveResponseMappingWithZeroedDoqIds()
    {
        return AssertVariedDnsMessageIdsUseSeparateStreamsWithZeroedDoqIds();
    }

    private static async Task AssertVariedDnsMessageIdsUseSeparateStreamsWithZeroedDoqIds()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[][] queries =
        [
            [0x12, 0x34, 0x41],
            [0xAB, 0xCD, 0x42],
            [0x00, 0x7F, 0x43],
        ];
        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, context.Query.Span[2])));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        foreach (byte[] query in queries)
        {
            DoqQueryResult result = await client.QueryAsync(query).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

            Assert.Equal([0x00, 0x00, query[2]], result.Response.ToArray());
        }

        DoqQueryContext[] observedQueries = handler.Queries;
        Assert.Equal(queries.Length, observedQueries.Length);
        for (int index = 0; index < queries.Length; index++)
        {
            Assert.Equal(index * 4, observedQueries[index].StreamId);
            Assert.Equal([0x00, 0x00, queries[index][2]], observedQueries[index].Query.ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0009")]
    [Requirement("RFC9250-S4-2-P7-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerWritesResponseOnTheSameQueryStream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xb9)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        byte[] encodedQuery = DoqMessageCodec.Encode([0x00, 0x00, 0x19]);
        await stream.WriteAsync(encodedQuery, 0, encodedQuery.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await stream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(10));

        DoqMessage response = await ReadSingleDoqMessageUntilFinAsync(stream).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xb9], response.Payload.ToArray());
        DoqQueryContext observed = Assert.Single(handler.Queries);
        Assert.Equal(stream.Id, observed.StreamId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LargeDnsResponsesFlowThroughTheDoqStreamPath()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] expectedResponse = CreateLargeDnsResponse(LargeDnsResponseLength);
        RecordingDoqHandler handler = new(_ =>
            new DoqQueryResult(expectedResponse));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(30));

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x20)).AsTask().WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Equal(LargeDnsResponseLength, result.Response.Length);
        Assert.Equal(expectedResponse, result.Response.ToArray());
        Assert.Equal(0x00, result.Response.Span[0]);
        Assert.Equal(0x00, result.Response.Span[1]);
    }

    [Fact]
    [Requirement("RFC9250-S4-3-2-P1-S2-R01")]
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
    [Requirement("RFC9250-S4-2-P5-S1-R01")]
    [Requirement("RFC9250-S4-2-P5-S3-R01")]
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
    [Requirement("RFC9250-S4-2-P5-S1-R01")]
    [Requirement("RFC9250-S4-2-P5-S3-R01")]
    [Requirement("REQ-QUIC-RFC9250-0017")]
    [Requirement("REQ-QUIC-RFC9250-0099")]
    [Requirement("REQ-QUIC-RFC9250-0100")]
    [Requirement("REQ-QUIC-RFC9250-0101")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ConcurrentQueryDoesNotReuseBlockedClientInitiatedBidirectionalStream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> first = client.QueryAsync(CreateDnsQuery(0x31)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Task<DoqQueryResult> second = client.QueryAsync(CreateDnsQuery(0x32)).AsTask();

        DoqQueryResult secondResult = await second.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xd5], secondResult.Response.ToArray());
        Assert.False(first.IsCompleted, "The first blocked query must not be reused to carry the second query.");
        Assert.Equal([0, 4], handler.StreamIds);

        handler.ReleaseFirstQuery();
        DoqQueryResult firstResult = await first.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal([0x00, 0x00, 0xd5], firstResult.Response.ToArray());
    }

    [Fact]
    [Requirement("RFC9250-S4-2-P9-R01")]
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
    [Requirement("RFC9250-S4-2-P6-S1-R01")]
    [Requirement("RFC9250-S4-2-P6-S1-R02")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task QueryAsyncSendsSelectedStreamQueryAndFin()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xb4)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(new byte[] { 0x12, 0x34, 0x44 }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xb4], result.Response.ToArray());
        DoqQueryContext observed = Assert.Single(handler.Queries);
        Assert.Equal(0, observed.StreamId);
        Assert.Equal([0x00, 0x00, 0x44], observed.Query.ToArray());
    }

    [Fact]
    [Requirement("RFC9250-S4-2-P6-S1-R01")]
    [Requirement("RFC9250-S4-2-P6-S1-R02")]
    [Requirement("RFC9250-S4-2-P9-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ServerDoesNotDispatchQueryBeforeClientStreamFin()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xb3)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        byte[] query = DoqMessageCodec.Encode([0x00, 0x00, 0x33]);
        await stream.WriteAsync(query, 0, query.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await Task.Delay(TimeSpan.FromMilliseconds(250));

        Assert.Empty(handler.Queries);

        await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        DoqMessage response = await ReadSingleDoqMessageUntilFinAsync(stream).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xb3], response.Payload.ToArray());
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0009")]
    [Requirement("RFC9250-S4-2-P7-R01")]
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
    [Requirement("REQ-QUIC-RFC9250-0002")]
    [Requirement("REQ-QUIC-RFC9250-0008")]
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
    [Requirement("REQ-QUIC-RFC9250-0034")]
    [Requirement("REQ-QUIC-RFC9250-0035")]
    [Requirement("RFC9250-S4-3-1-P1-S1-R02")]
    [Requirement("RFC9250-S4-3-1-P1-S4-R02")]
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
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
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
    [Requirement("RFC9250-S4-3-1-P3-R01")]
    [Requirement("RFC9250-S4-3-1-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task CancellationVolumeLimitClosesConnectionWithExcessiveLoad()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xd5)));
        await using TestServerContext context = await TestServerContext.StartAsync(
            handler,
            new DoqServerOptions { MaxCancellationRequests = 1 });
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        await using QuicStream firstStream = await connection
            .OpenOutboundStreamAsync(QuicStreamType.Bidirectional)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));
        byte[] partialFirstQuery = [0x00, 0x03, 0x00];
        await firstStream.WriteAsync(partialFirstQuery, 0, partialFirstQuery.Length).WaitAsync(TimeSpan.FromSeconds(10));
        firstStream.Abort(QuicAbortDirection.Write, (long)DoqErrorCode.RequestCancelled);
        await WaitForLocalWriteAbortAsync(firstStream);
        await WaitForPeerReadAbortAsync(firstStream, DoqErrorCode.RequestCancelled);

        await using QuicStream secondStream = await connection
            .OpenOutboundStreamAsync(QuicStreamType.Bidirectional)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));
        byte[] partialSecondQuery = [0x00, 0x03, 0x00];
        await secondStream.WriteAsync(partialSecondQuery, 0, partialSecondQuery.Length).WaitAsync(TimeSpan.FromSeconds(10));
        secondStream.Abort(QuicAbortDirection.Write, (long)DoqErrorCode.RequestCancelled);
        await WaitForLocalWriteAbortAsync(secondStream);
        await WaitForPeerReadAbortOrConnectionCloseAsync(secondStream, DoqErrorCode.RequestCancelled);

        QuicConnectionTerminalState terminalState = await WaitForConnectionAbortAsync(connection);

        Assert.Equal(QuicConnectionCloseOrigin.Remote, terminalState.Origin);
        Assert.Equal((ulong)DoqErrorCode.ExcessiveLoad, terminalState.Close.ApplicationErrorCode);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("RFC9250-S4-3-1-P1-S4-R01")]
    [Requirement("RFC9250-S4-3-1-P5-S1-R01")]
    [Requirement("RFC9250-S4-3-1-P5-S2-R01")]
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
    [Requirement("RFC9250-S4-3-2-P2-S1-R01")]
    [Requirement("RFC9250-S4-3-2-P2-S1-R02")]
    [Requirement("RFC9250-S4-3-2-P2-S2-R01")]
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
    [Requirement("RFC9250-S4-3-1-P3-S2-R01")]
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

        await using QuicStream secondStream = await connection
            .OpenOutboundStreamAsync(QuicStreamType.Bidirectional)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));
        byte[] partialQuery = [0x00];
        await secondStream.WriteAsync(partialQuery, 0, partialQuery.Length).WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            await secondStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (QuicException exception) when (exception.QuicError == QuicError.ConnectionAborted)
        {
            // The server may close for excessive load before the client's FIN is acknowledged.
        }

        QuicConnectionTerminalState terminalState = await WaitForConnectionAbortAsync(connection);

        Assert.Equal(QuicConnectionCloseOrigin.Remote, terminalState.Origin);
        Assert.Equal((ulong)DoqErrorCode.ExcessiveLoad, terminalState.Close.ApplicationErrorCode);

        handler.ReleaseFirstQuery();
        DoqException firstFailure = await Assert.ThrowsAsync<DoqException>(() =>
            first.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(DoqErrorCode.InternalError, firstFailure.ErrorCode);
    }

    [Fact]
    [Requirement("RFC9250-S4-4-P4-R01")]
    [Requirement("RFC9250-S4-4-P4-S1-R01")]
    [Requirement("RFC9250-S4-4-P6-S3-R01")]
    [Requirement("REQ-QUIC-RFC9250-0102")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReusesExistingHealthyConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xf0)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult first = await client.QueryAsync(CreateDnsQuery(0x01)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal([0x00, 0x00, 0xf0], first.Response.ToArray());

        DoqQueryResult second = await client.QueryAsync(CreateDnsQuery(0x02)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal([0x00, 0x00, 0xf0], second.Response.ToArray());

        Assert.Equal(2, handler.Queries.Length);
    }

    [Fact]
    [Requirement("RFC9250-S4-4-P4-R01")]
    [Requirement("RFC9250-S4-4-P4-S1-R01")]
    [Requirement("RFC9250-S4-4-P6-S3-R01")]
    [Requirement("RFC9250-S4-4-P6-S4-R01")]
    [Requirement("REQ-QUIC-RFC9250-0102")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task DoesNotReuseConnectionTooCloseToIdleTimeout()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xe0)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);

        QuicClientConnectionOptions clientOptions = context.CreateClientOptions();
        clientOptions.IdleTimeout = TimeSpan.FromSeconds(2);
        clientOptions.MaxInboundBidirectionalStreams = 2;

        await using DoqClient client = await DoqClient.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicConnection originalConnection = client.CurrentConnection;
        client.IdleTimeoutMargin = TimeSpan.FromSeconds(3);

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x03)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicConnection replacementConnection = client.CurrentConnection;

        Assert.Equal([0x00, 0x00, 0xe0], result.Response.ToArray());
        Assert.NotSame(originalConnection, replacementConnection);
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("RFC9250-S4-4-P6-S4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OpensReplacementConnectionWhenIdleTimeIsNotLowEnough()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xe1)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);

        QuicClientConnectionOptions clientOptions = context.CreateClientOptions();
        clientOptions.IdleTimeout = TimeSpan.FromSeconds(2);
        clientOptions.MaxInboundBidirectionalStreams = 2;

        await using DoqClient client = await DoqClient.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.IdleTimeoutMargin = TimeSpan.FromMilliseconds(100);

        DoqQueryResult first = await client.QueryAsync(CreateDnsQuery(0x03)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicConnection originalConnection = client.CurrentConnection;

        client.IdleTimeoutMargin = TimeSpan.FromMilliseconds(1500);
        await Task.Delay(TimeSpan.FromMilliseconds(750));

        DoqQueryResult second = await client.QueryAsync(CreateDnsQuery(0x04)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicConnection replacementConnection = client.CurrentConnection;

        Assert.Equal([0x00, 0x00, 0xe1], first.Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xe1], second.Response.ToArray());
        Assert.NotSame(originalConnection, replacementConnection);
        Assert.Equal(2, handler.Queries.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0071")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DiscardsConnectionBeforeIdleTimeoutExpires()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xd1)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);

        QuicClientConnectionOptions clientOptions = context.CreateClientOptions();
        clientOptions.IdleTimeout = TimeSpan.FromSeconds(2);

        await using DoqClient client = await DoqClient.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.IdleTimeoutMargin = TimeSpan.FromMilliseconds(100);

        DoqQueryResult first = await client.QueryAsync(CreateDnsQuery(0x04)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicConnection originalConnection = client.CurrentConnection;
        Assert.Equal([0x00, 0x00, 0xd1], first.Response.ToArray());

        client.IdleTimeoutMargin = TimeSpan.FromMilliseconds(1500);
        await Task.Delay(TimeSpan.FromMilliseconds(750));

        DoqQueryResult second = await client.QueryAsync(CreateDnsQuery(0x05)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicConnection replacementConnection = client.CurrentConnection;

        Assert.Equal([0x00, 0x00, 0xd1], second.Response.ToArray());
        Assert.NotSame(originalConnection, replacementConnection);
        Assert.Equal(2, handler.Queries.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0071")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task KeepsConnectionWhenIdleTimeIsSafelyBelowTimeout()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xd2)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);

        QuicClientConnectionOptions clientOptions = context.CreateClientOptions();
        clientOptions.IdleTimeout = TimeSpan.FromSeconds(5);

        await using DoqClient client = await DoqClient.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.IdleTimeoutMargin = TimeSpan.FromMilliseconds(500);

        DoqQueryResult first = await client.QueryAsync(CreateDnsQuery(0x06)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        DoqQueryResult second = await client.QueryAsync(CreateDnsQuery(0x07)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xd2], first.Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xd2], second.Response.ToArray());
        Assert.Equal(2, handler.Queries.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0074")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DisposeAsyncCompletesWithoutThrowing()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static _ =>
            new DoqQueryResult(CreateDnsResponse([0x00, 0x00, 0x10], 0xd0)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        await client.DisposeAsync();

        Exception? ex = await Record.ExceptionAsync(() =>
            client.QueryAsync(CreateDnsQuery(0x04)).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.IsType<ObjectDisposedException>(ex);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0072")]
    [Requirement("REQ-QUIC-RFC9250-0073")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DisposeAsyncWithOutstandingQueryClosesConnectionWithDoqNoError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicConnection connection = client.CurrentConnection;

        Task<DoqQueryResult> query = client.QueryAsync(CreateDnsQuery(0x08)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));

        await client.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        handler.ReleaseFirstQuery();

        QuicConnectionTerminalState terminalState = await WaitForConnectionAbortAsync(connection);
        Assert.Equal((ulong)DoqErrorCode.NoError, terminalState.Close.ApplicationErrorCode);

        Exception? queryException = await Record.ExceptionAsync(() => query.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.NotNull(queryException);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0072")]
    [Requirement("REQ-QUIC-RFC9250-0073")]
    [Requirement("REQ-QUIC-RFC9250-0074")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task DisposeAsyncWithoutOutstandingQueryDoesNotEmitDoqNoErrorClose()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static _ =>
            new DoqQueryResult(CreateDnsResponse([0x00, 0x00, 0x10], 0xd0)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicConnection connection = client.CurrentConnection;

        await client.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState? terminalState = await WaitBrieflyForTerminalStateAsync(connection);
        Assert.True(
            !terminalState.HasValue || terminalState.Value.Close.ApplicationErrorCode != (ulong)DoqErrorCode.NoError,
            "An idle client disposal must not use the outstanding-query DOQ_NO_ERROR close path.");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0111")]
    [Requirement("REQ-QUIC-RFC9250-0112")]
    [Requirement("REQ-QUIC-RFC9250-0113")]
    [Requirement("REQ-QUIC-RFC9250-0114")]
    [Requirement("REQ-QUIC-RFC9250-0115")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConcurrentZoneTransfersAreSupportedOnOneConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CoordinatedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> first = client.QueryAsync(CreateDnsZoneTransferQuery(0x01, DnsQTypeIxfr)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> second = client.QueryAsync(CreateDnsZoneTransferQuery(0x02, DnsQTypeAxfr)).AsTask();

        DoqQueryResult[] results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xa1], results[0].Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xa2], results[1].Response.ToArray());
        Assert.Contains(0L, handler.StreamIds);
        Assert.Contains(4L, handler.StreamIds);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0114")]
    [Requirement("REQ-QUIC-RFC9250-0115")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task QueuedZoneTransfersSentWithoutWaiting()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CoordinatedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> first = client.QueryAsync(CreateDnsZoneTransferQuery(0x01, DnsQTypeIxfr)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<DoqQueryResult> second = client.QueryAsync(CreateDnsZoneTransferQuery(0x02, DnsQTypeAxfr)).AsTask();

        DoqQueryResult[] results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xa1], results[0].Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xa2], results[1].Response.ToArray());
        Assert.Contains(0L, handler.StreamIds);
        Assert.Contains(4L, handler.StreamIds);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0111")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConcurrentIxfrTransfersUseSeparateStreamsOnOneConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CoordinatedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> first = client.QueryAsync(CreateDnsZoneTransferQuery(0x01, DnsQTypeIxfr)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<DoqQueryResult> second = client.QueryAsync(CreateDnsZoneTransferQuery(0x02, DnsQTypeIxfr)).AsTask();

        DoqQueryResult[] results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xa1], results[0].Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xa2], results[1].Response.ToArray());
        Assert.Contains(0L, handler.StreamIds);
        Assert.Contains(4L, handler.StreamIds);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0112")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConcurrentAxfrTransfersUseSeparateStreamsOnOneConnection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CoordinatedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> first = client.QueryAsync(CreateDnsZoneTransferQuery(0x01, DnsQTypeAxfr)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<DoqQueryResult> second = client.QueryAsync(CreateDnsZoneTransferQuery(0x02, DnsQTypeAxfr)).AsTask();

        DoqQueryResult[] results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xa1], results[0].Response.ToArray());
        Assert.Equal([0x00, 0x00, 0xa2], results[1].Response.ToArray());
        Assert.Contains(0L, handler.StreamIds);
        Assert.Contains(4L, handler.StreamIds);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0111")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task LaterIxfrTransferDoesNotWaitForBlockedEarlierIxfr()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> firstQuery = client.QueryAsync(CreateDnsZoneTransferQuery(0x01, DnsQTypeIxfr)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<DoqQueryResult> secondQuery = client.QueryAsync(CreateDnsZoneTransferQuery(0x02, DnsQTypeIxfr)).AsTask();
        DoqQueryResult secondResult = await secondQuery.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(firstQuery.IsCompleted);
        Assert.Equal([0x00, 0x00, 0xd5], secondResult.Response.ToArray());
        Assert.Contains(0L, handler.StreamIds);
        Assert.Contains(4L, handler.StreamIds);

        handler.ReleaseFirstQuery();
        await firstQuery.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0112")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task LaterAxfrTransferDoesNotWaitForBlockedEarlierAxfr()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> firstQuery = client.QueryAsync(CreateDnsZoneTransferQuery(0x01, DnsQTypeAxfr)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<DoqQueryResult> secondQuery = client.QueryAsync(CreateDnsZoneTransferQuery(0x02, DnsQTypeAxfr)).AsTask();
        DoqQueryResult secondResult = await secondQuery.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(firstQuery.IsCompleted);
        Assert.Equal([0x00, 0x00, 0xd5], secondResult.Response.ToArray());
        Assert.Contains(0L, handler.StreamIds);
        Assert.Contains(4L, handler.StreamIds);

        handler.ReleaseFirstQuery();
        await firstQuery.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0113")]
    [Requirement("REQ-QUIC-RFC9250-0114")]
    [Requirement("REQ-QUIC-RFC9250-0115")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task MixedZoneTransfersDoNotWaitForEarlierBlockedTransfer()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> firstQuery = client.QueryAsync(CreateDnsZoneTransferQuery(0x01, DnsQTypeIxfr)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<DoqQueryResult> secondQuery = client.QueryAsync(CreateDnsZoneTransferQuery(0x02, DnsQTypeAxfr)).AsTask();
        DoqQueryResult secondResult = await secondQuery.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(firstQuery.IsCompleted);
        Assert.Equal([0x00, 0x00, 0xd5], secondResult.Response.ToArray());
        Assert.Contains(0L, handler.StreamIds);
        Assert.Contains(4L, handler.StreamIds);

        handler.ReleaseFirstQuery();
        await firstQuery.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("RFC9250-S5-6-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OutOfOrderResponseDelivery()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> firstQuery = client.QueryAsync(CreateDnsQuery(0x01)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<DoqQueryResult> secondQuery = client.QueryAsync(CreateDnsQuery(0x02)).AsTask();
        DoqQueryResult secondResult = await secondQuery.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(firstQuery.IsCompleted);
        Assert.Equal([0x00, 0x00, 0xd5], secondResult.Response.ToArray());

        handler.ReleaseFirstQuery();
        DoqQueryResult firstResult = await firstQuery.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal([0x00, 0x00, 0xd5], firstResult.Response.ToArray());
    }

    [Fact]
    [Requirement("RFC9250-S5-6-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task LaterStreamResponseDoesNotWaitForBlockedEarlierStream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DelayedDoqHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<DoqQueryResult> firstQuery = client.QueryAsync(CreateDnsQuery(0x11)).AsTask();
        await handler.FirstQueryArrived.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<DoqQueryResult> secondQuery = client.QueryAsync(CreateDnsQuery(0x12)).AsTask();
        DoqQueryResult secondResult = await secondQuery.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(firstQuery.IsCompleted);
        Assert.Equal([0x00, 0x00, 0xd5], secondResult.Response.ToArray());

        handler.ReleaseFirstQuery();
        await firstQuery.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AllowsQueryWhenResumptionTicketIsNotMarkedUsed()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc4)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x24)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xc4], result.Response.ToArray());
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RejectsQueryWhenResumptionTicketIsAlreadyUsed()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc4)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.IsTicketUsed = true;

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x25)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(DoqErrorCode.InternalError, exception.ErrorCode);
        Assert.Contains("resumption ticket", exception.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AddressValidationTokenPolicyAllowsTokenWithSessionResumption()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc6)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(client.UseAddressValidationWithResumptionOnly);
        Assert.True(client.CanUseAddressValidationToken(usingSessionResumption: true));
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AddressValidationTokenPolicyRejectsTokenWithoutSessionResumptionByDefault()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc6)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(client.UseAddressValidationWithResumptionOnly);
        Assert.False(client.CanUseAddressValidationToken(usingSessionResumption: false));
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P3-S2-R01")]
    [Requirement("RFC9250-S5-5-4-P1-S4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AllowsQueryWhenConnectivityIsUnchanged()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc5)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.PriorConnectivityId = "wifi-a";
        client.ConnectivityId = "wifi-a";

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x26)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0xc5], result.Response.ToArray());
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P3-S2-R01")]
    [Requirement("RFC9250-S5-5-4-P1-S4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RejectsQueryAfterConnectivityChange()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0xc5)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.PriorConnectivityId = "wifi-a";
        client.ConnectivityId = "cell-b";

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x27)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(DoqErrorCode.InternalError, exception.ErrorCode);
        Assert.Contains("Connectivity has changed", exception.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0079")]
    [Requirement("RFC9250-S4-5-P2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AllowsZeroRttForReplayableQueryOpcode()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x77)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.AllowZeroRtt = true;

        DoqQueryResult result = await client.QueryAsync(CreateDnsQueryWithOpcode(0x28, opcode: 0)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0x77], result.Response.ToArray());
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0079")]
    [Requirement("RFC9250-S4-5-P2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RejectsZeroRttForNonReplayableOpcodeBeforeOpeningStream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x77)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.AllowZeroRtt = true;

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQueryWithOpcode(0x29, opcode: 2)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(DoqErrorCode.InternalError, exception.ErrorCode);
        Assert.Contains("non-replayable", exception.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0082")]
    [Requirement("REQ-QUIC-RFC9250-0083")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerRefusesNonReplayableZeroRttTransactionWithTooEarlyResponse()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x99)));
        DoqServerOptions serverOptions = new()
        {
            ZeroRttStreamDetector = static (_, _) => true,
        };
        await using TestServerContext context = await TestServerContext.StartAsync(handler, doqServerOptions: serverOptions);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(CreateDnsHeaderQueryWithOpcode(0x2c, opcode: 2)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True((result.Response.Span[2] & 0x80) != 0);
        Assert.Equal(5, result.Response.Span[3] & 0x0f);
        Assert.Contains(result.Response.ToArray(), value => value == 20);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0082")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ServerProcessesNonReplayableTransactionWhenZeroRttSignalIsAbsent()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x9a)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(CreateDnsHeaderQueryWithOpcode(0x2e, opcode: 2)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0x9a], result.Response.ToArray());
        DoqQueryContext observed = Assert.Single(handler.Queries);
        Assert.False(observed.IsZeroRtt);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0093")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerRejectsOversizedZeroRttResponseByAmplificationLimit()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static _ =>
            new DoqQueryResult(CreateDnsPayload(length: 32, marker: 0x93)));
        DoqServerOptions serverOptions = new()
        {
            ZeroRttStreamDetector = static (_, _) => true,
        };
        await using TestServerContext context = await TestServerContext.StartAsync(handler, doqServerOptions: serverOptions);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQueryWithOpcode(0x30, opcode: 0)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(DoqErrorCode.ProtocolError, exception.ErrorCode);
        DoqQueryContext observed = Assert.Single(handler.Queries);
        Assert.True(observed.IsZeroRtt);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0093")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ServerDoesNotApplyZeroRttAmplificationLimitWithoutZeroRttSignal()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static _ =>
            new DoqQueryResult(CreateDnsPayload(length: 32, marker: 0x94)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using DoqClient client = await DoqClient.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DoqQueryResult result = await client.QueryAsync(CreateDnsQueryWithOpcode(0x31, opcode: 0)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(32, result.Response.Length);
        Assert.Equal(0x94, result.Response.Span[2]);
        DoqQueryContext observed = Assert.Single(handler.Queries);
        Assert.False(observed.IsZeroRtt);
    }

    [Fact]
    [Requirement("RFC9250-S5-2-P3-S1-R01")]
    [Requirement("REQ-QUIC-RFC9250-0089")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task OpportunisticProfileRejectsQueryWhileEndpointIsBackedOff()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x88)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        QuicClientConnectionOptions clientOptions = context.CreateClientOptions();
        string endpoint = clientOptions.RemoteEndPoint!.ToString()!;
        DoqFallbackCache fallbackCache = new(TimeSpan.FromMinutes(5));
        fallbackCache.RecordFailure(endpoint);

        await using DoqClient client = await DoqClient.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.Profile = DoqClientProfile.Opportunistic;
        client.FallbackCache = fallbackCache;

        DoqException exception = await Assert.ThrowsAsync<DoqException>(() =>
            client.QueryAsync(CreateDnsQuery(0x2a)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(DoqErrorCode.InternalError, exception.ErrorCode);
        Assert.Contains("temporarily backed off", exception.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0089")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task KeyPinnedEndpointMayRetryDuringShortBackoffWindow()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x89)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        QuicClientConnectionOptions clientOptions = context.CreateClientOptions();
        string endpoint = clientOptions.RemoteEndPoint!.ToString()!;
        DoqFallbackCache fallbackCache = new(TimeSpan.FromSeconds(30));
        fallbackCache.RecordFailure(endpoint);

        await using DoqClient client = await DoqClient.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.Profile = DoqClientProfile.Opportunistic;
        client.FallbackCache = fallbackCache;
        client.KeyPinnedEndpoints.Add(endpoint);

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x2f)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0x89], result.Response.ToArray());
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("RFC9250-S5-2-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OpportunisticProfileAllowsQueryAfterBackoffIsCleared()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingDoqHandler handler = new(static context =>
            new DoqQueryResult(CreateDnsResponse(context.Query.Span, 0x88)));
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        QuicClientConnectionOptions clientOptions = context.CreateClientOptions();
        string endpoint = clientOptions.RemoteEndPoint!.ToString()!;
        DoqFallbackCache fallbackCache = new(TimeSpan.FromMinutes(5));
        fallbackCache.RecordFailure(endpoint);
        fallbackCache.ClearFailure(endpoint);

        await using DoqClient client = await DoqClient.ConnectAsync(clientOptions).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        client.Profile = DoqClientProfile.Opportunistic;
        client.FallbackCache = fallbackCache;

        DoqQueryResult result = await client.QueryAsync(CreateDnsQuery(0x2b)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([0x00, 0x00, 0x88], result.Response.ToArray());
        Assert.Single(handler.Queries);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0019")]
    [Requirement("REQ-QUIC-RFC9250-0020")]
    [Requirement("REQ-QUIC-RFC9250-0021")]
    [Requirement("RFC9250-S4-3-1-P3-R01")]
    [Requirement("RFC9250-S4-3-1-P3-S1-R01")]
    [Requirement("RFC9250-S4-3-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DanglingStreamAndCancellationLimitPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        AssertContainsAll(
            lifecycleTests,
            "DanglingStreamLimitClosesConnectionWithExcessiveLoad",
            "CancellationVolumeLimitClosesConnectionWithExcessiveLoad",
            "MaxDanglingStreams = 1",
            "MaxCancellationRequests = 1",
            "DoqErrorCode.ExcessiveLoad");
        AssertContainsAll(
            server,
            "MaxDanglingStreams",
            "MaxCancellationRequests",
            "CloseConnectionAsync(connection, DoqErrorCode.ExcessiveLoad");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0034")]
    [Requirement("REQ-QUIC-RFC9250-0035")]
    [Requirement("REQ-QUIC-RFC9250-0038")]
    [Requirement("RFC9250-S4-3-1-P1-S1-R02")]
    [Requirement("RFC9250-S4-3-1-P1-S4-R01")]
    [Requirement("RFC9250-S4-3-1-P1-S4-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StopSendingAndCancellationPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        AssertContainsAll(
            lifecycleTests,
            "QueryCancellationAbortsReadSideAndLeavesConnectionUsable",
            "ServerDoesNotDispatchQueryWhenStopSendingReceivedBeforeFin",
            "LateStopSendingAfterResponseIsDiscardedAndConnectionRemainsUsable",
            "stream.Abort(QuicAbortDirection.Write, (long)DoqErrorCode.RequestCancelled)");
        AssertContainsAll(client, "AbortStreamRead(stream, DoqErrorCode.RequestCancelled)");
        AssertContainsAll(server, "AbortStreamWrite(stream, DoqErrorCode.RequestCancelled)");
    }

    [Fact]
    [Requirement("RFC9250-S4-3-1-P5-S1-R01")]
    [Requirement("RFC9250-S4-3-1-P5-S2-R01")]
    [Requirement("RFC9250-S4-3-2-P1-S2-R01")]
    [Requirement("RFC9250-S4-3-2-P2-S1-R01")]
    [Requirement("RFC9250-S4-3-2-P2-S1-R02")]
    [Requirement("RFC9250-S4-3-2-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamServfailAndInternalErrorPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        AssertContainsAll(
            lifecycleTests,
            "EarlyResetBeforeFinDoesNotDispatchQueryAndLeavesConnectionUsable",
            "QueryAsync_PropagatesServfailResponseCodeFromHandler",
            "HandlerFailureAbortsStreamWithInternalErrorAndClosesConnection",
            "DoqErrorCode.InternalError",
            "CreateDnsServfailResponse");
        AssertContainsAll(
            server,
            "AbortStreamWrite(stream, DoqErrorCode.InternalError)",
            "CloseConnectionAsync(connection, DoqErrorCode.ProtocolError");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0099")]
    [Requirement("REQ-QUIC-RFC9250-0100")]
    [Requirement("REQ-QUIC-RFC9250-0101")]
    [Requirement("RFC9250-S4-2-P5-S1-R01")]
    [Requirement("RFC9250-S4-2-P5-S3-R01")]
    [Requirement("RFC9250-S5-6-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConcurrentQueryAndResponseStreamPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        AssertContainsAll(
            lifecycleTests,
            "ConcurrentQueriesUseNextClientInitiatedBidirectionalStreamsOnOneConnection",
            "ConcurrentQueryDoesNotReuseBlockedClientInitiatedBidirectionalStream",
            "OutOfOrderResponseDelivery",
            "LaterStreamResponseDoesNotWaitForBlockedEarlierStream",
            "Assert.Equal([0, 4], handler.StreamIds)");
        AssertContainsAll(client, "OpenOutboundStreamAsync(QuicStreamType.Bidirectional");
        AssertContainsAll(
            server,
            "AcceptInboundStreamAsync",
            "streamTasks.Add(HandleQueryStreamAsync",
            "Task.WhenAll(streamTasks)");
    }

    [Fact]
    [Requirement("RFC9250-S4-2-P6-S1-R02")]
    [Requirement("RFC9250-S4-2-P7-R02")]
    [Requirement("RFC9250-S4-2-P9-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamFinAndDeferredProcessingPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");

        AssertContainsAll(
            lifecycleTests,
            "QueryAsyncSendsSelectedStreamQueryAndFin",
            "ServerDoesNotDispatchQueryBeforeClientStreamFin",
            "ServerWritesResponseOnTheSameQueryStream",
            "CompleteWritesAsync");
        AssertContainsAll(
            stream,
            "ReadSingleMessageUntilFinAsync",
            "WriteMessageAndCompleteAsync",
            "CompleteWritesAsync");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0071")]
    [Requirement("REQ-QUIC-RFC9250-0072")]
    [Requirement("REQ-QUIC-RFC9250-0073")]
    [Requirement("REQ-QUIC-RFC9250-0074")]
    [Requirement("RFC9250-S4-4-P4-R01")]
    [Requirement("RFC9250-S4-4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ExplicitCloseAndIdleMonitoringPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");

        AssertContainsAll(
            lifecycleTests,
            "DiscardsConnectionBeforeIdleTimeoutExpires",
            "KeepsConnectionWhenIdleTimeIsSafelyBelowTimeout",
            "DisposeAsyncWithOutstandingQueryClosesConnectionWithDoqNoError",
            "DisposeAsyncWithoutOutstandingQueryDoesNotEmitDoqNoErrorClose",
            "DoqErrorCode.NoError");
        AssertContainsAll(
            client,
            "IdleTimeoutMargin",
            "CloseAsync((long)DoqErrorCode.NoError",
            "CurrentConnection");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0102")]
    [Requirement("RFC9250-S4-4-P6-S3-R01")]
    [Requirement("RFC9250-S4-4-P6-S4-R01")]
    [Requirement("RFC9250-S5-2-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionReuseReplacementAndBackoffPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");

        AssertContainsAll(
            lifecycleTests,
            "ReusesExistingHealthyConnection",
            "DoesNotReuseConnectionTooCloseToIdleTimeout",
            "OpensReplacementConnectionWhenIdleTimeIsNotLowEnough",
            "OpportunisticProfileRejectsQueryWhileEndpointIsBackedOff",
            "OpportunisticProfileAllowsQueryAfterBackoffIsCleared");
        AssertContainsAll(
            client,
            "FallbackCache",
            "DoqClientProfile.Opportunistic",
            "IdleTimeoutMargin");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0111")]
    [Requirement("REQ-QUIC-RFC9250-0112")]
    [Requirement("REQ-QUIC-RFC9250-0113")]
    [Requirement("REQ-QUIC-RFC9250-0114")]
    [Requirement("REQ-QUIC-RFC9250-0115")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZoneTransferConcurrencyPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        AssertContainsAll(
            lifecycleTests,
            "ConcurrentZoneTransfersAreSupportedOnOneConnection",
            "QueuedZoneTransfersSentWithoutWaiting",
            "ConcurrentIxfrTransfersUseSeparateStreamsOnOneConnection",
            "ConcurrentAxfrTransfersUseSeparateStreamsOnOneConnection",
            "LaterIxfrTransferDoesNotWaitForBlockedEarlierIxfr",
            "LaterAxfrTransferDoesNotWaitForBlockedEarlierAxfr",
            "MixedZoneTransfersDoNotWaitForEarlierBlockedTransfer",
            "DnsQTypeIxfr",
            "DnsQTypeAxfr");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0079")]
    [Requirement("REQ-QUIC-RFC9250-0080")]
    [Requirement("REQ-QUIC-RFC9250-0082")]
    [Requirement("REQ-QUIC-RFC9250-0083")]
    [Requirement("RFC9250-S4-5-P1-R01")]
    [Requirement("RFC9250-S4-5-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ZeroRttReplayabilityPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        AssertContainsAll(
            lifecycleTests,
            "AllowsZeroRttForReplayableQueryOpcode",
            "RejectsZeroRttForNonReplayableOpcodeBeforeOpeningStream",
            "ServerRefusesNonReplayableZeroRttTransactionWithTooEarlyResponse",
            "ServerProcessesNonReplayableTransactionWhenZeroRttSignalIsAbsent",
            "ZeroRttStreamDetector");
        AssertContainsAll(client, "AllowZeroRtt", "non-replayable");
        AssertContainsAll(server, "ZeroRttStreamDetector", "TooEarly");
    }

    [Fact]
    [Requirement("RFC9250-S5-5-3-P3-S1-R01")]
    [Requirement("RFC9250-S5-5-3-P3-S2-R01")]
    [Requirement("RFC9250-S5-5-3-P4-S3-R01")]
    [Requirement("RFC9250-S5-5-4-P1-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResumptionTicketAddressValidationAndPrivacyPoliciesRemainTraceLinked()
    {
        string lifecycleTests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");

        AssertContainsAll(
            lifecycleTests,
            "AllowsQueryWhenResumptionTicketIsNotMarkedUsed",
            "RejectsQueryWhenResumptionTicketIsAlreadyUsed",
            "AddressValidationTokenPolicyAllowsTokenWithSessionResumption",
            "AddressValidationTokenPolicyRejectsTokenWithoutSessionResumptionByDefault",
            "AllowsQueryWhenConnectivityIsUnchanged",
            "RejectsQueryAfterConnectivityChange");
        AssertContainsAll(
            client,
            "IsTicketUsed",
            "PriorConnectivityId",
            "ConnectivityId",
            "UseAddressValidationWithResumptionOnly");
    }

    private static void AssertContainsAll(string source, params string[] expectedValues)
    {
        foreach (string expected in expectedValues)
        {
            Assert.Contains(expected, source, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ stream lifecycle tests.");
    }

    private static byte[] CreateDnsQuery(byte idLowByte)
        => [0x12, idLowByte, (byte)(0x10 + idLowByte)];

    private static byte[] CreateDnsQueryWithOpcode(byte idLowByte, int opcode)
        => [0x12, idLowByte, (byte)(opcode << 3)];

    private static byte[] CreateDnsHeaderQueryWithOpcode(byte idLowByte, int opcode)
        =>
        [
            0x12, idLowByte, (byte)(opcode << 3), 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

    private static byte[] CreateDnsZoneTransferQuery(byte idLowByte, ushort qtype)
    {
        byte[] query =
        [
            0x12, idLowByte, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            0x03, (byte)'c', (byte)'o', (byte)'m',
            0x00,
            0x00, 0x00,
            0x00, 0x01,
        ];

        query[^4] = (byte)(qtype >> 8);
        query[^3] = (byte)qtype;
        return query;
    }

    private static byte[] CreateDnsResponse(ReadOnlySpan<byte> query, byte responseMarker)
        => [0x00, query.Length > 1 ? query[1] : (byte)0x00, responseMarker];

    private static byte CreateCoordinatedResponseMarker(ReadOnlySpan<byte> query, bool isFirst)
    {
        if (TryReadQuestionType(query, out ushort qtype) &&
            (qtype == DnsQTypeIxfr || qtype == DnsQTypeAxfr))
        {
            return isFirst ? (byte)0xa1 : (byte)0xa2;
        }

        return query.Length > 2 && query[2] == 0x11 ? (byte)0xa1 : (byte)0xa2;
    }

    private static bool TryReadQuestionType(ReadOnlySpan<byte> query, out ushort qtype)
    {
        qtype = default;
        const int dnsHeaderLength = 12;
        if (query.Length < dnsHeaderLength || query[4] != 0x00 || query[5] != 0x01)
        {
            return false;
        }

        int offset = dnsHeaderLength;
        while (offset < query.Length && query[offset] != 0)
        {
            int labelLength = query[offset];
            offset += 1 + labelLength;
        }

        if (offset >= query.Length)
        {
            return false;
        }

        offset++;
        if (offset > query.Length - 4)
        {
            return false;
        }

        qtype = (ushort)((query[offset] << 8) | query[offset + 1]);
        return true;
    }

    private static byte[] CreateDnsPayload(int length, byte marker)
    {
        byte[] payload = new byte[length];
        payload[0] = 0x00;
        payload[1] = 0x00;
        payload[2] = marker;
        return payload;
    }

    private static byte[] CreateLargeDnsResponse(int payloadLength)
    {
        byte[] response = new byte[payloadLength];
        response[0] = 0x00;
        response[1] = 0x00;
        response[2] = 0x81;
        response[3] = 0x80;

        for (int i = 4; i < response.Length; i++)
        {
            response[i] = (byte)(i & 0xff);
        }

        return response;
    }

    private static byte[] CreateDnsServfailResponse()
        => [0x00, 0x00, 0x81, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    private static async Task DrainStreamAsync(QuicStream stream)
    {
        byte[] buffer = new byte[16];
        while (await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false) != 0)
        {
        }
    }

    private static async Task<DoqMessage> ReadSingleDoqMessageUntilFinAsync(QuicStream stream)
    {
        byte[] buffer = new byte[256];
        List<byte> pending = [];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
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

    private static async Task<QuicConnectionTerminalState?> WaitBrieflyForTerminalStateAsync(QuicConnection connection)
    {
        TimeSpan pollInterval = TimeSpan.FromMilliseconds(25);
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddMilliseconds(250);

        while (DateTimeOffset.UtcNow < deadline)
        {
            if (connection.Runtime.TerminalState is QuicConnectionTerminalState terminalState)
            {
                return terminalState;
            }

            await Task.Delay(pollInterval).ConfigureAwait(false);
        }

        return connection.Runtime.TerminalState;
    }

    private static async Task WaitForLocalWriteAbortAsync(QuicStream stream)
    {
        QuicException exception = await Assert.ThrowsAsync<QuicException>(() =>
            stream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(QuicError.OperationAborted, exception.QuicError);
        Assert.Null(exception.ApplicationErrorCode);
    }

    private static async Task WaitForPeerReadAbortAsync(QuicStream stream, DoqErrorCode expectedErrorCode)
    {
        QuicException exception = await Assert.ThrowsAsync<QuicException>(() =>
            stream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(QuicError.StreamAborted, exception.QuicError);
        Assert.Equal((long)expectedErrorCode, exception.ApplicationErrorCode);
    }

    private static async Task WaitForPeerReadAbortOrConnectionCloseAsync(QuicStream stream, DoqErrorCode expectedErrorCode)
    {
        QuicException exception = await Assert.ThrowsAsync<QuicException>(() =>
            stream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(10)));

        if (exception.QuicError == QuicError.ConnectionAborted)
        {
            return;
        }

        Assert.Equal(QuicError.StreamAborted, exception.QuicError);
        Assert.Equal((long)expectedErrorCode, exception.ApplicationErrorCode);
    }

    private static async Task<QuicConnectionTerminalState> WaitForConnectionAbortAsync(QuicConnection connection)
    {
        TimeSpan pollInterval = TimeSpan.FromMilliseconds(25);
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(30);

        while (true)
        {
            if (connection.Runtime.TerminalState is QuicConnectionTerminalState terminalState)
            {
                return terminalState;
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

            byte marker = CreateCoordinatedResponseMarker(context.Query.Span, isFirst);
            return new DoqQueryResult(CreateDnsResponse(context.Query.Span, marker));
        }
    }

    private sealed class DelayedDoqHandler : IDoqQueryHandler
    {
        private readonly List<long> streamIds = [];
        private readonly TaskCompletionSource<object?> firstQueryArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<object?> releaseFirstQuery = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int queryCount;

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

        public void ReleaseFirstQuery()
            => releaseFirstQuery.TrySetResult(null);

        public async ValueTask<DoqQueryResult> HandleAsync(DoqQueryContext context, CancellationToken cancellationToken = default)
        {
            lock (streamIds)
            {
                streamIds.Add(context.StreamId);
            }

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
