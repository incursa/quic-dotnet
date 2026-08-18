// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(Http3LoopbackTestCollection.Name)]
public sealed class Http3MinimalServerTests
{
    [Fact]
    public void RequestConstructor_DefensivelyCopiesBody()
    {
        byte[] body = [0x01, 0x02, 0x03];

        Http3Request request = new(
            "POST",
            "https",
            "localhost",
            "/upload",
            [],
            body);
        body[0] = 0xFF;

        Assert.Equal([0x01, 0x02, 0x03], request.Body.ToArray());
    }

    [Fact]
    public void RequestOwnedBodyConstructor_BorrowsBodyMemory()
    {
        byte[] body = [0x01, 0x02, 0x03];

        Http3Request request = new(
            "POST",
            "https",
            "localhost",
            "/upload",
            protocol: null,
            headers: [],
            body: body,
            copyBody: false);

        Assert.True(MemoryMarshal.TryGetArray(request.Body, out ArraySegment<byte> segment));
        Assert.Same(body, segment.Array);
    }

    [Fact]
    public void ServerResponseConstructor_DefensivelyCopiesBody()
    {
        byte[] body = [0x01, 0x02, 0x03];

        Http3ServerResponse response = new(200, body);
        body[0] = 0xFF;

        Assert.Equal([0x01, 0x02, 0x03], response.Body.ToArray());
        Assert.False(response.CacheEncodedHeaders);
    }

    [Fact]
    public void ServerResponseCreateFromImmutableBody_BorrowsBodyMemory()
    {
        byte[] body = [0x01, 0x02, 0x03];

        Http3ServerResponse response = Http3ServerResponse.CreateFromImmutableBody(200, body);

        Assert.True(MemoryMarshal.TryGetArray(response.Body, out ArraySegment<byte> segment));
        Assert.Same(body, segment.Array);
        Assert.True(response.CacheEncodedHeaders);

        byte[] dataFrame = [0x00, 0x02, 0x01, 0x02];
        Assert.Same(dataFrame, response.CacheSingleDataFrame(dataFrame));
        Assert.Same(dataFrame, response.GetCachedSingleDataFrame());

        byte[] completeFrame = [0x01, 0x02, 0x03, 0x04];
        Assert.Same(completeFrame, response.CacheCompleteResponseFrame(completeFrame));
        Assert.Same(completeFrame, response.GetCachedCompleteResponseFrame());
    }

    [Fact]
    public void ServerResponseCreateFromImmutableBodyAndHeaders_BorrowsBodyAndHeaders()
    {
        byte[] body = [0x01, 0x02, 0x03];
        QPackFieldLine[] headers = [new("content-type", "application/octet-stream")];

        Http3ServerResponse response = Http3ServerResponse.CreateFromImmutableBodyAndHeaders(200, body, headers);

        Assert.True(MemoryMarshal.TryGetArray(response.Body, out ArraySegment<byte> segment));
        Assert.Same(body, segment.Array);
        Assert.Same(headers, response.Headers);
        Assert.True(response.CacheEncodedHeaders);
    }

    [Fact]
    public async Task InMemoryRouteHandler_MapGet_CopiesCallerBodyAndCachesStoredResponse()
    {
        byte[] body = [0x01, 0x02, 0x03];
        Http3InMemoryRouteHandler handler = new();
        handler.MapGet("/cached", body);
        body[0] = 0xFF;

        QPackFieldLine[] headers =
        [
            new(":method", "GET"),
            new(":scheme", "https"),
            new(":authority", "localhost"),
            new(":path", "/cached"),
        ];
        Http3Request request = new("GET", "https", "localhost", "/cached", headers);

        Http3ServerResponse response = await handler.HandleAsync(request);

        Assert.Equal([0x01, 0x02, 0x03], response.Body.ToArray());
        Assert.True(response.CacheEncodedHeaders);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task GetAsync_StaticRoute_ReturnsSuccess()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/hello", "hello from server"));

        Http3Response response = await context.GetAsync("/hello");

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("hello from server", System.Text.Encoding.UTF8.GetString(response.Body));
        Assert.True(response.StreamCompleted);
    }

    [Fact]
    public async Task GetAsync_StaticRoute_CachesCompleteFixedResponseFrame()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        Http3InMemoryRouteHandler handler = new();
        handler.MapGetText("/hello", "hello");
        Http3Request request = new(
            "GET",
            "https",
            "localhost",
            "/hello",
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "localhost"),
                new QPackFieldLine(":path", "/hello"),
            ]);
        Http3ServerResponse cachedResponse = await handler.HandleAsync(request);

        Assert.Null(cachedResponse.GetCachedCompleteResponseFrame());

        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        Http3Response response = await context.GetAsync("/hello");

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("hello", System.Text.Encoding.UTF8.GetString(response.Body));
        Assert.NotNull(cachedResponse.GetCachedCompleteResponseFrame());
    }

    [Fact]
    public async Task GetAsync_HeadersOnlyHandler_UsesFastPathWithoutFullRequest()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        HeadersOnlyFastPathHandler handler = new();

        await using TestServerContext context = await TestServerContext.StartAsync(handler);

        Http3Response response = await context.GetAsync("/fast");

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("fast", System.Text.Encoding.UTF8.GetString(response.Body));
        Assert.Equal(1, handler.HeadersOnlyCalls);
        Assert.Equal(0, handler.FullRequestCalls);
        Assert.Equal("GET", handler.Method);
        Assert.Equal("/fast", handler.Path);
        Assert.NotEmpty(handler.Headers);
    }

    [Fact]
    public async Task HeadersOnlyHandler_ReleasesCapacityAcrossRepeatedConcurrentBatches()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        const int BatchSize = 100;
        const int BatchCount = 6;
        HeadersOnlyFastPathHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        for (int batch = 0; batch < BatchCount; batch++)
        {
            Task<Http3Response>[] responseTasks = Enumerable.Range(0, BatchSize)
                .Select(async requestIndex =>
                {
                    await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                    await WriteGetRequestAsync(requestStream, $"/fast?batch={batch}&request={requestIndex}");
                    return await ReadResponseAsync(requestStream);
                })
                .ToArray();

            Http3Response[] responses = await Task.WhenAll(responseTasks).WaitAsync(TimeSpan.FromSeconds(20));
            Assert.All(responses, static response =>
            {
                Assert.Equal(200, response.StatusCode);
                Assert.True(response.StreamCompleted);
            });
        }

        Assert.Equal(BatchSize * BatchCount, handler.HeadersOnlyCalls);
        Assert.Equal(0, handler.FullRequestCalls);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9114-S9-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(65_536, 12)]
    [InlineData(1_048_576, 4)]
    public async Task RepeatedLargeResponses_CompleteWithExactBodyAndFin(int responseSize, int requestCount)
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(responseSize);
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGet("/large", body));

        for (int requestIndex = 0; requestIndex < requestCount; requestIndex++)
        {
            RecordingHttp3DiagnosticsSink diagnostics = new();
            Http3Response response = await context.GetAsync($"/large?request={requestIndex}", diagnosticsSink: diagnostics);

            Assert.Equal(200, response.StatusCode);
            QPackFieldLine contentLength = Assert.Single(
                response.Headers,
                static header => header.Name == "content-length");
            Assert.Equal(responseSize.ToString(), contentLength.Value);
            Assert.Equal(
                responseSize,
                diagnostics.Events
                    .Where(static diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameReceived
                        && diagnostic.FrameType == Http3FrameType.Data)
                    .Sum(static diagnostic => diagnostic.PayloadLength));
            Assert.Equal(body.Length, response.Body.Length);
            Assert.Equal(body, response.Body);
            Assert.True(response.StreamCompleted);
            Assert.Contains(
                diagnostics.Events,
                diagnostic => diagnostic.Kind == Http3DiagnosticKind.ResponseCompleted
                    && diagnostic.PayloadLength == responseSize);
        }
    }

    [Fact]
    public async Task ImmutableLargeResponse_CachesCompleteSerializedFrameSequence()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(65_536);
        Http3ServerResponse serverResponse = Http3ServerResponse.CreateFromImmutableBody(
            200,
            body,
            [new QPackFieldLine("content-length", body.Length.ToString())]);
        await using TestServerContext context = await TestServerContext.StartAsync(
            new FixedResponseHandler(serverResponse));

        Task<Http3Response>[] responseTasks = Enumerable.Range(0, 8)
            .Select(index => context.GetAsync($"/large?request={index}").AsTask())
            .ToArray();
        Http3Response[] responses = await Task.WhenAll(responseTasks);
        byte[]? firstCachedFrame = serverResponse.GetCachedCompleteResponseFrame();

        Assert.All(responses, response =>
        {
            Assert.Equal(body, response.Body);
            Assert.True(response.StreamCompleted);
        });
        Assert.NotNull(firstCachedFrame);
        Assert.True(firstCachedFrame.Length > body.Length);

        Http3Response laterResponse = await context.GetAsync("/large?request=later");
        Assert.Equal(body, laterResponse.Body);
        Assert.Same(firstCachedFrame, serverResponse.GetCachedCompleteResponseFrame());
    }

    [Fact]
    public async Task ImmutableResponseAboveCompleteCacheLimit_RemainsUncached()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes((2 * 1024 * 1024) + 1);
        Http3ServerResponse serverResponse = Http3ServerResponse.CreateFromImmutableBody(
            200,
            body,
            [new QPackFieldLine("content-length", body.Length.ToString())]);
        await using TestServerContext context = await TestServerContext.StartAsync(
            new FixedResponseHandler(serverResponse));

        Http3Response response = await context.GetAsync("/large");

        Assert.Equal(body, response.Body);
        Assert.True(response.StreamCompleted);
        Assert.Null(serverResponse.GetCachedCompleteResponseFrame());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DynamicQpackRequest_UsesPeerEncoderStreamAndReturnsSuccess()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/dynamic-qpack", "dynamic hello"),
            diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        Assert.True(encoder.TrySetDynamicTableCapacity(220, out byte[] capacityInstruction));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "localhost"), out byte[] authorityInstruction));
        Assert.True(encoder.TryInsert(new QPackFieldLine(":path", "/dynamic-qpack"), out byte[] pathInstruction));

        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(qpackMaxTableCapacity: 220, qpackBlockedStreams: 1),
            [capacityInstruction, authorityInstruction, pathInstruction]);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QPackFieldSectionEncodeResult requestFieldSection = encoder.EncodeFieldSection(
            checked((ulong)requestStream.Id),
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "localhost"),
                new QPackFieldLine(":path", "/dynamic-qpack"),
            ]);

        byte[] headersFrame = Http3FrameWriter.WriteHeaders(requestFieldSection.EncodedFieldSection);
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("dynamic hello", System.Text.Encoding.UTF8.GetString(response.Body));
        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.QPackInstructionReceived
                && diagnostic.StreamKind == Http3StreamKind.QPackEncoder);
        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.RequestStarted
                && diagnostic.Path == "/dynamic-qpack");
        await WaitForDiagnosticAsync(
            diagnostics,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.ResponseCompleted
                && diagnostic.StatusCode == 200);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PeerQPackDecoderStream_ZeroInsertCountIncrement_ClosesConnectionWithDecoderStreamError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler());
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] settingsBytes = Http3SettingsWriter.WriteInitialControlStream(new Http3Settings());
        await controlStream.WriteAsync(settingsBytes, 0, settingsBytes.Length).WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream decoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteStreamTypeAsync(decoderStream, Http3StreamType.QPackDecoder);
        byte[] invalidInsertCountIncrement = [0x00];
        await decoderStream.WriteAsync(invalidInsertCountIncrement, 0, invalidInsertCountIncrement.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await decoderStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)QPackErrorCode.DecoderStreamError, terminalState.Close.ApplicationErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PeerControlStream_ClosedAfterSettings_ClosesConnectionWithClosedCriticalStream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler());
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] settingsBytes = Http3SettingsWriter.WriteInitialControlStream(new Http3Settings());
        await controlStream.WriteAsync(settingsBytes, 0, settingsBytes.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await controlStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)Http3ErrorCode.ClosedCriticalStream, terminalState.Close.ApplicationErrorCode);
    }

    [Theory]
    [InlineData((ulong)Http3FrameType.Data)]
    [InlineData((ulong)Http3FrameType.Headers)]
    [Requirement("REQ-QUIC-RFC9114-S6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PeerControlStream_InvalidFrame_ClosesConnectionWithFrameUnexpected(ulong frameType)
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler());
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteStreamTypeAsync(controlStream, Http3StreamType.Control);
        byte[] invalidFrame = Http3FrameWriter.WriteFrame(frameType, []);
        await controlStream.WriteAsync(invalidFrame, 0, invalidFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await controlStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)Http3ErrorCode.FrameUnexpected, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, Http3ErrorCode.FrameUnexpected);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PeerControlStream_SecondSettingsFrame_ClosesConnectionWithFrameUnexpected()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler());
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] settingsBytes = Http3SettingsWriter.WriteInitialControlStream(new Http3Settings());
        await controlStream.WriteAsync(settingsBytes, 0, settingsBytes.Length).WaitAsync(TimeSpan.FromSeconds(10));
        byte[] secondSettings = Http3SettingsWriter.WriteSettingsFrame(new Http3Settings());
        await controlStream.WriteAsync(secondSettings, 0, secondSettings.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await controlStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)Http3ErrorCode.FrameUnexpected, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, Http3ErrorCode.FrameUnexpected);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PeerQPackDecoderStream_Closed_ClosesConnectionWithClosedCriticalStream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler(), diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream decoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteStreamTypeAsync(decoderStream, Http3StreamType.QPackDecoder);
        await WaitForDiagnosticAsync(
            diagnostics,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.StreamOpened
                && diagnostic.StreamId == decoderStream.Id
                && diagnostic.StreamKind == Http3StreamKind.QPackDecoder);
        await decoderStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection, diagnostics);

        Assert.Equal((ulong)Http3ErrorCode.ClosedCriticalStream, terminalState.Close.ApplicationErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S5-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RequestInvalidQPackStaticIndex_ClosesConnectionWithDecompressionFailed()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler());
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] invalidFieldSection = [0x00, 0x00, .. QPackInteger.Encode(99, 6, 0xC0)];
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(invalidFieldSection);
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)QPackErrorCode.DecompressionFailed, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, QPackErrorCode.DecompressionFailed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PeerQPackEncoderStream_CapacityAbovePeerSetting_ClosesConnectionWithEncoderStreamError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler());
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] settingsBytes = Http3SettingsWriter.WriteInitialControlStream(new Http3Settings());
        await controlStream.WriteAsync(settingsBytes, 0, settingsBytes.Length).WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream encoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteStreamTypeAsync(encoderStream, Http3StreamType.QPackEncoder);
        byte[] capacityInstruction = QPackInteger.Encode(1, 5, 0x20);
        await encoderStream.WriteAsync(capacityInstruction, 0, capacityInstruction.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await encoderStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)QPackErrorCode.EncoderStreamError, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, QPackErrorCode.EncoderStreamError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task InMemoryRouteHandler_MissingGet_Returns404()
    {
        Http3InMemoryRouteHandler handler = new();
        Http3Request request = new(
            "GET",
            "https",
            "localhost",
            "/missing",
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "localhost"),
                new QPackFieldLine(":path", "/missing"),
            ]);

        Http3ServerResponse response = await handler.HandleAsync(request);

        Assert.Equal(404, response.StatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task MalformedRequestHeaders_ClosesConnectionWithMessageError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/hello", "hello"));
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] malformedHeaders = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", "/hello"),
        ]);
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(malformedHeaders);
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)Http3ErrorCode.MessageError, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, Http3ErrorCode.MessageError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task GetWithoutRequestStreamFin_DispatchesAfterHeaders()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/no-fin", "response before fin"));
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteGetRequestHeadersAsync(requestStream, "/no-fin");

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("response before fin", System.Text.Encoding.UTF8.GetString(response.Body));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_DispatchesTunnelHandlerAndEchoesMessage()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        EchoWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        byte[] clientFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "hello tunnel"u8,
            [0x10, 0x20, 0x30, 0x40]);
        await requestStream.WriteAsync(clientFrame, 0, clientFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage echoed = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);

        Assert.Equal(Http3WebSocketOpcode.Text, echoed.Opcode);
        Assert.Equal("echo:hello tunnel", System.Text.Encoding.UTF8.GetString(echoed.Payload.Span));
        Assert.Equal("/socket", webSocketHandler.Path);
        Assert.Equal("hello tunnel", System.Text.Encoding.UTF8.GetString(webSocketHandler.Payload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0030")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_Http3Client_OpensClientTunnelAndEchoesMessage()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        EchoWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using Http3Client client = await Http3Client.ConnectAsync(
                context.CreateClientOptions(),
                new Http3ClientOptions { Settings = new Http3Settings(enableConnectProtocol: 1) })
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        await using Http3WebSocketClientTunnelContext tunnel = await client
            .OpenWebSocketAsync(new Uri($"https://localhost:{context.Endpoint.Port}/socket"))
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));
        await tunnel.WriteMessageAsync(Http3WebSocketOpcode.Binary, "client payload"u8.ToArray())
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage echoed = await tunnel.ReadMessageAsync()
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ?? throw new InvalidOperationException("The WebSocket tunnel ended before the echo arrived.");

        Assert.Equal(200, tunnel.StatusCode);
        Assert.Contains(tunnel.ResponseHeaders, header => header.Name == ":status" && header.Value == "200");
        Assert.Equal(Http3WebSocketOpcode.Binary, echoed.Opcode);
        Assert.Equal("echo:client payload", System.Text.Encoding.UTF8.GetString(echoed.Payload.Span));
        Assert.Equal("/socket", webSocketHandler.Path);
        Assert.Equal("client payload", System.Text.Encoding.UTF8.GetString(webSocketHandler.Payload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0030")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WebSocketExtendedConnect_Http3Client_RequiresEnableConnectSetting()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = new EchoWebSocketHandler());
        await using Http3Client client = await Http3Client.ConnectAsync(context.CreateClientOptions())
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        Http3Exception exception = await Assert.ThrowsAsync<Http3Exception>(
            async () => await client.OpenWebSocketAsync(new Uri($"https://localhost:{context.Endpoint.Port}/socket")));

        Assert.Equal(Http3ErrorCode.SettingsError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0031")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_Http3Client_CarriesSubprotocolRequestAndAcceptResponseHeaders()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        string offeredSubprotocols = string.Empty;
        EchoWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options =>
            {
                options.WebSocketHandler = webSocketHandler;
                options.WebSocketAcceptResponseHeadersSelector = request =>
                {
                    offeredSubprotocols = Assert.Single(
                        request.Headers,
                        header => header.Name == "sec-websocket-protocol").Value;
                    return [new QPackFieldLine("sec-websocket-protocol", "superchat")];
                };
            });
        await using Http3Client client = await Http3Client.ConnectAsync(
                context.CreateClientOptions(),
                new Http3ClientOptions { Settings = new Http3Settings(enableConnectProtocol: 1) })
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        await using Http3WebSocketClientTunnelContext tunnel = await client
            .OpenWebSocketAsync(
                new Uri($"https://localhost:{context.Endpoint.Port}/socket"),
                [new QPackFieldLine("sec-websocket-protocol", "chat, superchat")])
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));
        await tunnel.WriteMessageAsync(Http3WebSocketOpcode.Text, "metadata"u8.ToArray())
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage echoed = await tunnel.ReadMessageAsync()
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ?? throw new InvalidOperationException("The WebSocket tunnel ended before the echo arrived.");

        Assert.Equal("chat, superchat", offeredSubprotocols);
        Assert.Contains(tunnel.ResponseHeaders, header => header.Name == "sec-websocket-protocol" && header.Value == "superchat");
        Assert.Equal("echo:metadata", System.Text.Encoding.UTF8.GetString(echoed.Payload.Span));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0017")]
    [Requirement("REQ-QUIC-RFC9220-0018")]
    [Requirement("REQ-QUIC-RFC9220-0019")]
    [Requirement("REQ-QUIC-RFC9220-0022")]
    [Requirement("REQ-QUIC-RFC9220-0030")]
    [Requirement("REQ-QUIC-RFC9220-0031")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "InteropProof")]
    public async Task WebSocketExtendedConnect_LocalPeerHarness_ExercisesClientServerLifecycle()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] bufferedPayload = CreateDeterministicBytes(6_000);
        LocalPeerProofWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options =>
            {
                options.WebSocketHandler = webSocketHandler;
                options.WebSocketAcceptResponseHeadersSelector = request =>
                {
                    string offered = Assert.Single(
                        request.Headers,
                        header => header.Name == "sec-websocket-protocol").Value;
                    Assert.Equal("proof.v1, fallback", offered);
                    return [new QPackFieldLine("sec-websocket-protocol", "proof.v1")];
                };
            });
        await using Http3Client client = await Http3Client.ConnectAsync(
                context.CreateClientOptions(),
                new Http3ClientOptions { Settings = new Http3Settings(enableConnectProtocol: 1) })
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        await using Http3WebSocketClientTunnelContext tunnel = await client
            .OpenWebSocketAsync(
                new Uri($"https://localhost:{context.Endpoint.Port}/socket?proof=local"),
                [new QPackFieldLine("sec-websocket-protocol", "proof.v1, fallback")])
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage serverPing = await tunnel.ReadMessageAsync()
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ?? throw new InvalidOperationException("The WebSocket tunnel ended before the server ping arrived.");
        await tunnel.EchoPingAsync(serverPing).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] fragmentedTextFirst = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "frag"u8,
            [0x21, 0x22, 0x23, 0x24],
            final: false);
        byte[] interleavedPing = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Ping,
            "client-proof"u8,
            [0x31, 0x32, 0x33, 0x34]);
        byte[] fragmentedTextFinal = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Continuation,
            "mented text"u8,
            [0x41, 0x42, 0x43, 0x44]);
        await tunnel.Stream.WriteAsync(fragmentedTextFirst, 0, fragmentedTextFirst.Length)
            .WaitAsync(TimeSpan.FromSeconds(10));
        await tunnel.Stream.WriteAsync(interleavedPing, 0, interleavedPing.Length)
            .WaitAsync(TimeSpan.FromSeconds(10));
        await tunnel.Stream.WriteAsync(fragmentedTextFinal, 0, fragmentedTextFinal.Length)
            .WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage clientPingPong = await tunnel.ReadMessageAsync()
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ?? throw new InvalidOperationException("The WebSocket tunnel ended before the client ping pong arrived.");
        Http3WebSocketMessage textEcho = await tunnel.ReadMessageAsync()
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ?? throw new InvalidOperationException("The WebSocket tunnel ended before the text echo arrived.");
        await tunnel.WriteMessageAsync(Http3WebSocketOpcode.Binary, bufferedPayload)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage binaryEcho = await tunnel.ReadMessageAsync()
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ?? throw new InvalidOperationException("The WebSocket tunnel ended before the buffered binary echo arrived.");
        await tunnel.CloseAsync(1000, "done").AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage closeEcho = await tunnel.ReadMessageAsync()
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ?? throw new InvalidOperationException("The WebSocket tunnel ended before the close echo arrived.");
        await webSocketHandler.CompletionAsync.WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(closeEcho);
        Assert.Equal(200, tunnel.StatusCode);
        Assert.Contains(tunnel.ResponseHeaders, header => header.Name == ":status" && header.Value == "200");
        Assert.Contains(tunnel.ResponseHeaders, header => header.Name == "sec-websocket-protocol" && header.Value == "proof.v1");
        Assert.Equal(Http3WebSocketOpcode.Ping, serverPing.Opcode);
        Assert.Equal("server-proof", System.Text.Encoding.UTF8.GetString(serverPing.Payload.Span));
        Assert.Equal(Http3WebSocketOpcode.Pong, clientPingPong.Opcode);
        Assert.Equal("client-proof", System.Text.Encoding.UTF8.GetString(clientPingPong.Payload.Span));
        Assert.Equal(Http3WebSocketOpcode.Text, textEcho.Opcode);
        Assert.Equal("echo:fragmented text", System.Text.Encoding.UTF8.GetString(textEcho.Payload.Span));
        Assert.Equal(Http3WebSocketOpcode.Binary, binaryEcho.Opcode);
        Assert.Equal(bufferedPayload, binaryEcho.Payload.ToArray());
        Assert.Equal(Http3WebSocketOpcode.Close, closeEcho.Opcode);
        Assert.Equal((ushort)1000, closeStatus.StatusCode);
        Assert.Equal("done", closeStatus.Reason);
        Assert.Equal("/socket?proof=local", webSocketHandler.Path);
        Assert.Equal("proof.v1, fallback", webSocketHandler.RequestSubprotocols);
        Assert.True(webSocketHandler.ObservedPong);
        Assert.True(webSocketHandler.ObservedClientPing);
        Assert.Equal("fragmented text", System.Text.Encoding.UTF8.GetString(webSocketHandler.TextPayload));
        Assert.Equal(bufferedPayload.Length, webSocketHandler.BinaryPayloadLength);
        Assert.Equal((ushort)1000, webSocketHandler.CloseStatusCode);
        Assert.Equal("done", webSocketHandler.CloseReason);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0031")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WebSocketExtendedConnect_Http3Client_RejectsAdditionalPseudoHeaders()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = new EchoWebSocketHandler());
        await using Http3Client client = await Http3Client.ConnectAsync(
                context.CreateClientOptions(),
                new Http3ClientOptions { Settings = new Http3Settings(enableConnectProtocol: 1) })
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        await Assert.ThrowsAsync<ArgumentException>(
            async () => await client.OpenWebSocketAsync(
                new Uri($"https://localhost:{context.Endpoint.Port}/socket"),
                [new QPackFieldLine(":path", "/other")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_CloseFrame_EchoesCloseAndCompletesWrites()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CloseEchoWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        byte[] closePayload = [0x03, 0xE8, .. System.Text.Encoding.UTF8.GetBytes("done")];
        byte[] closeFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Close,
            closePayload,
            [0xAA, 0xBB, 0xCC, 0xDD]);
        await requestStream.WriteAsync(closeFrame, 0, closeFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage closeEcho = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        int eof = await requestStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(closeEcho);
        Assert.Equal(Http3WebSocketOpcode.Close, closeEcho.Opcode);
        Assert.Equal((ushort)1000, closeStatus.StatusCode);
        Assert.Equal("done", closeStatus.Reason);
        Assert.Equal(0, eof);
        Assert.Equal((ushort)1000, webSocketHandler.StatusCode);
        Assert.Equal("done", webSocketHandler.Reason);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0019")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_PingFrame_EchoesPongAndContinuesTunnel()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        PingPongWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        byte[] pingFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Ping,
            "alive"u8,
            [0x01, 0x02, 0x03, 0x04]);
        await requestStream.WriteAsync(pingFrame, 0, pingFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage pong = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);

        byte[] textFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "after ping"u8,
            [0x05, 0x06, 0x07, 0x08]);
        await requestStream.WriteAsync(textFrame, 0, textFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage echoed = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);

        Assert.Equal(Http3WebSocketOpcode.Pong, pong.Opcode);
        Assert.Equal("alive", System.Text.Encoding.UTF8.GetString(pong.Payload.Span));
        Assert.Equal(Http3WebSocketOpcode.Text, echoed.Opcode);
        Assert.Equal("echo:after ping", System.Text.Encoding.UTF8.GetString(echoed.Payload.Span));
        Assert.True(webSocketHandler.ObservedPing);
        Assert.Equal("after ping", System.Text.Encoding.UTF8.GetString(webSocketHandler.Payload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_ApplicationClose_WritesCloseAndCompletesWrites()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        ApplicationCloseWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        byte[] clientFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "unsupported"u8,
            [0x10, 0x20, 0x30, 0x40]);
        await requestStream.WriteAsync(clientFrame, 0, clientFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage close = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        int eof = await requestStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(close);
        Assert.Equal(Http3WebSocketOpcode.Close, close.Opcode);
        Assert.Equal((ushort)1003, closeStatus.StatusCode);
        Assert.Equal("unsupported", closeStatus.Reason);
        Assert.Equal(0, eof);
        Assert.Equal("unsupported", System.Text.Encoding.UTF8.GetString(webSocketHandler.Payload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0021")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WebSocketExtendedConnect_MalformedFrame_WritesProtocolErrorClose()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        ProtocolErrorCloseWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        byte[] unmaskedClientFrame = Http3WebSocketFrameWriter.WriteUnmasked(Http3WebSocketOpcode.Text, "bad"u8);
        await requestStream.WriteAsync(unmaskedClientFrame, 0, unmaskedClientFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage close = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        int eof = await requestStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(close);
        Assert.Equal(Http3WebSocketOpcode.Close, close.Opcode);
        Assert.Equal((ushort)1002, closeStatus.StatusCode);
        Assert.Equal("protocol error", closeStatus.Reason);
        Assert.Equal(0, eof);
        await webSocketHandler.ObservedProtocolErrorAsync.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(webSocketHandler.ObservedProtocolError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0022")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_ServerPing_PreservesTunnelAfterPong()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        ServerPingWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        Http3WebSocketMessage ping = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        Assert.Equal(Http3WebSocketOpcode.Ping, ping.Opcode);
        Assert.Equal("server-check", System.Text.Encoding.UTF8.GetString(ping.Payload.Span));

        byte[] pongFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Pong,
            ping.Payload.Span,
            [0x01, 0x02, 0x03, 0x04]);
        await requestStream.WriteAsync(pongFrame, 0, pongFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        byte[] textFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "after pong"u8,
            [0x05, 0x06, 0x07, 0x08]);
        await requestStream.WriteAsync(textFrame, 0, textFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage echoed = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);

        Assert.Equal(Http3WebSocketOpcode.Text, echoed.Opcode);
        Assert.Equal("echo:after pong", System.Text.Encoding.UTF8.GetString(echoed.Payload.Span));
        Assert.True(webSocketHandler.ObservedPong);
        Assert.Equal("after pong", System.Text.Encoding.UTF8.GetString(webSocketHandler.Payload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0024")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_ConfiguredKeepAlive_PingsWithoutBlockingTunnelData()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        KeepAliveObservedWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options =>
            {
                options.WebSocketHandler = webSocketHandler;
                options.WebSocketKeepAliveInterval = TimeSpan.FromMilliseconds(25);
            });
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        Http3WebSocketMessage ping = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        Assert.Equal(Http3WebSocketOpcode.Ping, ping.Opcode);
        Assert.Equal(0, ping.Payload.Length);

        byte[] pongFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Pong,
            ping.Payload.Span,
            [0x01, 0x02, 0x03, 0x04]);
        await requestStream.WriteAsync(pongFrame, 0, pongFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        byte[] textFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "after keepalive"u8,
            [0x05, 0x06, 0x07, 0x08]);
        await requestStream.WriteAsync(textFrame, 0, textFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage echoed = await ReadUntilWebSocketMessageAsync(
            requestStream,
            message => message.Opcode == Http3WebSocketOpcode.Text,
            Http3EndpointRole.Client);

        Assert.Equal("echo:after keepalive", System.Text.Encoding.UTF8.GetString(echoed.Payload.Span));
        Assert.True(webSocketHandler.ObservedPong);
        Assert.Equal("after keepalive", System.Text.Encoding.UTF8.GetString(webSocketHandler.Payload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0026")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_ConfiguredKeepAlive_UsesConfiguredPingPayload()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        KeepAliveObservedWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options =>
            {
                options.WebSocketHandler = webSocketHandler;
                options.WebSocketKeepAliveInterval = TimeSpan.FromMilliseconds(25);
                options.WebSocketKeepAlivePayload = "ka:socket"u8.ToArray();
            });
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        Http3WebSocketMessage ping = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        Assert.Equal(Http3WebSocketOpcode.Ping, ping.Opcode);
        Assert.Equal("ka:socket", System.Text.Encoding.UTF8.GetString(ping.Payload.Span));

        byte[] pongFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Pong,
            ping.Payload.Span,
            [0x01, 0x02, 0x03, 0x04]);
        await requestStream.WriteAsync(pongFrame, 0, pongFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        byte[] textFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Text,
            "after keepalive payload"u8,
            [0x05, 0x06, 0x07, 0x08]);
        await requestStream.WriteAsync(textFrame, 0, textFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage echoed = await ReadUntilWebSocketMessageAsync(
            requestStream,
            message => message.Opcode == Http3WebSocketOpcode.Text,
            Http3EndpointRole.Client);

        Assert.Equal("echo:after keepalive payload", System.Text.Encoding.UTF8.GetString(echoed.Payload.Span));
        Assert.True(webSocketHandler.ObservedPong);
        Assert.Equal("after keepalive payload", System.Text.Encoding.UTF8.GetString(webSocketHandler.Payload));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0025")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_TcpForwarder_ForwardsBinaryPayloadThroughTcpEcho()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] clientPayload = "from websocket"u8.ToArray();
        await using TcpEchoServerContext tcpContext = TcpEchoServerContext.Start(clientPayload.Length);
        TcpForwardingWebSocketHandler webSocketHandler = new(tcpContext.Endpoint);
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        byte[] binaryFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Binary,
            clientPayload,
            [0x01, 0x02, 0x03, 0x04]);
        await requestStream.WriteAsync(binaryFrame, 0, binaryFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage forwarded = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        byte[] observedTcpPayload = await tcpContext.ObservedPayloadAsync.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(Http3WebSocketOpcode.Binary, forwarded.Opcode);
        Assert.Equal("tcp:from websocket", System.Text.Encoding.UTF8.GetString(forwarded.Payload.Span));
        Assert.Equal(clientPayload, observedTcpPayload);

        byte[] closePayload = Http3WebSocketCloseFrameParser.FormatPayload(1000, null);
        byte[] closeFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Close,
            closePayload,
            [0x05, 0x06, 0x07, 0x08]);
        await requestStream.WriteAsync(closeFrame, 0, closeFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage close = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        int eof = await requestStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(Http3WebSocketOpcode.Close, close.Opcode);
        Assert.Equal(0, eof);
        await webSocketHandler.CompletionAsync.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(webSocketHandler.Completed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0029")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_TcpForwarder_BoundsTcpResponseChunks()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        const int forwarderBufferSize = 5;
        byte[] firstPayload = "alpha"u8.ToArray();
        byte[] secondPayload = "-beta"u8.ToArray();
        byte[] expectedTcpPayload = "alpha-beta"u8.ToArray();
        byte[] tcpResponse = "tcp:alpha-beta:0123456789"u8.ToArray();
        await using TcpEchoServerContext tcpContext = TcpEchoServerContext.Start(expectedTcpPayload.Length, _ => tcpResponse);
        TcpForwardingWebSocketHandler webSocketHandler = new(
            tcpContext.Endpoint,
            new Http3WebSocketTcpForwarderOptions { BufferSize = forwarderBufferSize });
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        byte[] firstFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Binary,
            firstPayload,
            [0x01, 0x02, 0x03, 0x04]);
        byte[] secondFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Binary,
            secondPayload,
            [0x05, 0x06, 0x07, 0x08]);
        await requestStream.WriteAsync(firstFrame, 0, firstFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.WriteAsync(secondFrame, 0, secondFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        using MemoryStream responseBytes = new();
        while (responseBytes.Length < tcpResponse.Length)
        {
            foreach (Http3WebSocketMessage responseChunk in await ReadWebSocketMessagesAsync(requestStream, Http3EndpointRole.Client))
            {
                Assert.Equal(Http3WebSocketOpcode.Binary, responseChunk.Opcode);
                Assert.InRange(responseChunk.Payload.Length, 1, forwarderBufferSize);
                await responseBytes.WriteAsync(responseChunk.Payload);
            }
        }

        byte[] observedTcpPayload = await tcpContext.ObservedPayloadAsync.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(expectedTcpPayload, observedTcpPayload);
        Assert.Equal(tcpResponse, responseBytes.ToArray());

        byte[] closePayload = Http3WebSocketCloseFrameParser.FormatPayload(1000, null);
        byte[] closeFrame = Http3WebSocketFrameWriter.WriteMasked(
            Http3WebSocketOpcode.Close,
            closePayload,
            [0x09, 0x0A, 0x0B, 0x0C]);
        await requestStream.WriteAsync(closeFrame, 0, closeFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketMessage close = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        int eof = await requestStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(Http3WebSocketOpcode.Close, close.Opcode);
        Assert.Equal(0, eof);
        await webSocketHandler.CompletionAsync.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(webSocketHandler.Completed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0023")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WebSocketExtendedConnect_HandlerException_WritesInternalErrorClose()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        ThrowingWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        Http3WebSocketMessage close = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        int eof = await requestStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(close);
        Assert.Equal(Http3WebSocketOpcode.Close, close.Opcode);
        Assert.Equal((ushort)1011, closeStatus.StatusCode);
        Assert.Equal("internal error", closeStatus.Reason);
        Assert.Equal(0, eof);
        Assert.True(webSocketHandler.ObservedDispatch);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0027")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_HandlerException_UsesConfiguredClosePolicy()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        ThrowingWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options =>
            {
                options.WebSocketHandler = webSocketHandler;
                options.WebSocketHandlerExceptionCloseStatusCode = 1008;
                options.WebSocketHandlerExceptionCloseReason = "policy";
            });
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        Http3WebSocketMessage close = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        int eof = await requestStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(close);
        Assert.Equal(Http3WebSocketOpcode.Close, close.Opcode);
        Assert.Equal((ushort)1008, closeStatus.StatusCode);
        Assert.Equal("policy", closeStatus.Reason);
        Assert.Equal(0, eof);
        Assert.True(webSocketHandler.ObservedDispatch);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0028")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WebSocketExtendedConnect_HandlerException_UsesDynamicClosePolicy()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        ThrowingWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options =>
            {
                options.WebSocketHandler = webSocketHandler;
                options.WebSocketHandlerExceptionClosePolicySelector = exception => exception is InvalidOperationException
                    ? new Http3WebSocketClosePolicy(1012, "mapped")
                    : null;
            });
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteWebSocketConnectHeadersAsync(requestStream, "/socket");

        QPackFieldLine[] responseHeaders = await ReadResponseHeadersAsync(requestStream);
        QPackFieldLine status = Assert.Single(responseHeaders, header => header.Name == ":status");
        Assert.Equal("200", status.Value);

        Http3WebSocketMessage close = await ReadOneWebSocketMessageAsync(requestStream, Http3EndpointRole.Client);
        int eof = await requestStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10));

        Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(close);
        Assert.Equal(Http3WebSocketOpcode.Close, close.Opcode);
        Assert.Equal((ushort)1012, closeStatus.StatusCode);
        Assert.Equal("mapped", closeStatus.Reason);
        Assert.Equal(0, eof);
        Assert.True(webSocketHandler.ObservedDispatch);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9220-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task UnsupportedExtendedConnect_WithWebSocketHandler_Returns501WithoutDispatch()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        EchoWebSocketHandler webSocketHandler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/fallback", "fallback"),
            configureHttp3Options: options => options.WebSocketHandler = webSocketHandler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(
            connection,
            new Http3Settings(enableConnectProtocol: 1),
            []);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteExtendedConnectHeadersAsync(requestStream, "/unsupported", "webtransport");
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(Http3ExtendedConnect.UnsupportedProtocolStatusCode, response.StatusCode);
        Assert.Equal(string.Empty, webSocketHandler.Path);
        Assert.Empty(webSocketHandler.Payload);
    }

    [Theory]
    [InlineData("/plaintext")]
    [InlineData("/json")]
    public async Task HeadersOnlyGet_DeliversEmptyBodyToHandler(string path)
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CaptureRequestHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteGetRequestAsync(requestStream, path);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("GET", handler.Method);
        Assert.Equal(path, handler.Path);
        Assert.Empty(handler.Body);
        Assert.Contains(handler.Headers, header => header.Name == ":path" && header.Value == path);
    }

    [Fact]
    public async Task HeadersOnlyGet_WithFragmentedHeaders_DeliversRequest()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CaptureRequestHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteFragmentedGetRequestAsync(requestStream, "/plaintext");

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("GET", handler.Method);
        Assert.Equal("/plaintext", handler.Path);
        Assert.Empty(handler.Body);
        Assert.Contains(handler.Headers, header => header.Name == ":path" && header.Value == "/plaintext");
    }

    [Fact]
    public async Task PostDataRequest_DeliversBodyToHandler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CaptureBodyHandler handler = new();
        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            handler,
            diagnostics,
            static options =>
            {
                options.InitialReceiveWindowSizes = new QuicReceiveWindowSizes
                {
                    Connection = 16 * 1024 * 1024,
                    LocallyInitiatedBidirectionalStream = 16 * 1024 * 1024,
                    RemotelyInitiatedBidirectionalStream = 16 * 1024 * 1024,
                    UnidirectionalStream = 16 * 1024 * 1024,
                };
            });
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WritePostRequestAsync(requestStream, "/upload", "hello body"u8.ToArray());

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.True(
            response.StatusCode == 200,
            string.Join(" | ", diagnostics.Events.Select(static diagnostic => $"{diagnostic.Kind}:{diagnostic.ErrorCode}:{diagnostic.Message}")));
        Assert.Equal("hello body", System.Text.Encoding.UTF8.GetString(handler.Body));
    }

    [Fact]
    public async Task PostDataRequest_WithEmptyDataFrame_DeliversEmptyBodyToHandler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CaptureBodyHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WritePostRequestAsync(requestStream, "/upload", [], includeContentLength: true);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Empty(handler.Body);
    }

    [Fact]
    public async Task PostDataRequest_WithMultipleDataFrames_PreservesBodyOrdering()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CaptureBodyHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WritePostRequestDataFramesAsync(requestStream, "/upload", ["hello "u8.ToArray(), "ordered body"u8.ToArray()]);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("hello ordered body", System.Text.Encoding.UTF8.GetString(handler.Body));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S4-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task StreamingPost_EchoesDataBeforeRequestFin_AndPreservesFallbackHandler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DuplexStreamingHandler handler = new();
        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler, diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using (QuicStream fallbackStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10)))
        {
            await WritePostRequestAsync(fallbackStream, "/buffered", "fallback"u8.ToArray(), includeContentLength: true);
            Http3Response fallbackResponse = await ReadResponseAsync(fallbackStream);
            Assert.Equal(200, fallbackResponse.StatusCode);
            Assert.Equal("buffered:fallback", System.Text.Encoding.UTF8.GetString(fallbackResponse.Body));
        }

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] first = "first "u8.ToArray();
        byte[] second = "second"u8.ToArray();
        QPackFieldLine[] fields =
        [
            new QPackFieldLine(":method", "POST"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", "/duplex"),
            new QPackFieldLine("content-length", (first.Length + second.Length).ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new QPackFieldLine("content-type", "application/octet-stream"),
        ];
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(fields));
        byte[] firstDataFrame = Http3FrameWriter.WriteData(first);
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.WriteAsync(firstDataFrame, 0, firstDataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3FrameReader responseReader = new();
        List<byte> responseBody = [];
        bool responseHeadersSeen = false;
        byte[] readBuffer = new byte[4096];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(10));
        while (responseBody.Count < first.Length)
        {
            int bytesRead = await requestStream.ReadAsync(readBuffer, 0, readBuffer.Length, timeout.Token);
            Assert.True(
                bytesRead != 0,
                string.Join(" | ", diagnostics.Events.Select(static diagnostic => $"{diagnostic.Kind}:{diagnostic.ErrorCode}:{diagnostic.Message}")));
            foreach (Http3Frame frame in responseReader.Read(readBuffer.AsSpan(0, bytesRead)))
            {
                responseHeadersSeen |= frame is Http3HeadersFrame;
                if (frame is Http3DataFrame dataFrame)
                {
                    responseBody.AddRange(dataFrame.Data.ToArray());
                }
            }
        }

        Assert.True(responseHeadersSeen);
        Assert.Equal(first, responseBody);
        Assert.False(requestStream.WritesClosed.IsCompleted);

        byte[] secondDataFrame = Http3FrameWriter.WriteData(second);
        await requestStream.WriteAsync(secondDataFrame, 0, secondDataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        while (true)
        {
            int bytesRead = await requestStream.ReadAsync(readBuffer, 0, readBuffer.Length, timeout.Token);
            if (bytesRead == 0)
            {
                foreach (Http3Frame frame in responseReader.Complete())
                {
                    if (frame is Http3DataFrame dataFrame)
                    {
                        responseBody.AddRange(dataFrame.Data.ToArray());
                    }
                }

                break;
            }

            foreach (Http3Frame frame in responseReader.Read(readBuffer.AsSpan(0, bytesRead)))
            {
                if (frame is Http3DataFrame dataFrame)
                {
                    responseBody.AddRange(dataFrame.Data.ToArray());
                }
            }
        }

        Assert.Equal([.. first, .. second], responseBody);
        Assert.Equal(1, handler.StreamingCalls);
        Assert.Equal(1, handler.BufferedCalls);
    }

    [Theory]
    [InlineData(4 * 1024)]
    [InlineData(16 * 1024)]
    [Requirement("REQ-QUIC-RFC9114-S4-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task StreamingPost_EchoesFrameBoundaryDataBeforeRequestFin(int payloadLength)
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        DuplexStreamingHandler handler = new();
        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler, diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] payload = new byte[payloadLength];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(index % 251);
        }
        QPackFieldLine[] fields =
        [
            new QPackFieldLine(":method", "POST"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", "/duplex"),
            new QPackFieldLine("content-length", payloadLength.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new QPackFieldLine("content-type", "application/octet-stream"),
        ];
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(fields));
        byte[] dataFrame = Http3FrameWriter.WriteData(payload);
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.WriteAsync(dataFrame, 0, dataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));

        Http3FrameReader responseReader = new();
        List<byte> responseBody = [];
        byte[] readBuffer = new byte[16 * 1024];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(10));
        while (responseBody.Count < payload.Length)
        {
            int bytesRead = await requestStream.ReadAsync(readBuffer, 0, readBuffer.Length, timeout.Token);
            Assert.True(
                bytesRead != 0,
                string.Join(" | ", diagnostics.Events.Select(static diagnostic => $"{diagnostic.Kind}:{diagnostic.ErrorCode}:{diagnostic.Message}")));
            foreach (Http3Frame frame in responseReader.Read(readBuffer.AsSpan(0, bytesRead)))
            {
                if (frame is Http3DataFrame responseData)
                {
                    responseBody.AddRange(responseData.Data.ToArray());
                }
            }
        }

        Assert.Equal(payload, responseBody);
        Assert.False(requestStream.WritesClosed.IsCompleted);
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        while (await requestStream.ReadAsync(readBuffer, 0, readBuffer.Length, timeout.Token) != 0)
        {
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S4-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamingPost_ContentLengthMismatch_ClosesConnectionWithMessageError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(new DuplexStreamingHandler(), diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QPackFieldLine[] fields =
        [
            new QPackFieldLine(":method", "POST"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", "/duplex"),
            new QPackFieldLine("content-length", "12"),
            new QPackFieldLine("content-type", "application/octet-stream"),
        ];
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(fields));
        byte[] shortDataFrame = Http3FrameWriter.WriteData("short"u8);
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.WriteAsync(shortDataFrame, 0, shortDataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (DateTimeOffset.UtcNow < deadline
            && !diagnostics.Events.Any(static diagnostic => diagnostic.Kind == Http3DiagnosticKind.ConnectionClosed))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25));
        }

        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.Error
                && diagnostic.ErrorCode == Http3ErrorCode.MessageError.ToString());
        Assert.Contains(diagnostics.Events, static diagnostic => diagnostic.Kind == Http3DiagnosticKind.ConnectionClosed);
    }

    [Fact]
    public async Task PostDataRequest_WithFragmentedFrames_PreservesBody()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        CaptureBodyHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteFragmentedPostRequestAsync(requestStream, "/upload", "fragmented body"u8.ToArray());

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("fragmented body", System.Text.Encoding.UTF8.GetString(handler.Body));
    }

    [Fact]
    public async Task PostDataRequest_WithLargeSingleDataFrame_PreservesBodyAcrossReads()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(256 * 1024);
        CaptureBodyHandler handler = new();
        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler, diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WritePostRequestAsync(requestStream, "/upload", body, includeContentLength: true);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.True(
            response.StatusCode == 200,
            string.Join(" | ", diagnostics.Events.Select(static diagnostic => $"{diagnostic.Kind}:{diagnostic.ErrorCode}:{diagnostic.Message}")));
        Assert.Equal(body, handler.Body);
        Http3DiagnosticEvent dataFrame = Assert.Single(
            diagnostics.Events,
            static diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameReceived
                && diagnostic.FrameType == Http3FrameType.Data);
        Assert.Equal(body.Length, dataFrame.PayloadLength);
    }

    [Fact]
    public async Task StreamingCapableHandler_BufferedFallback_PreservesLargeBodyAcrossSegments()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(1024 * 1024);
        DuplexStreamingHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WritePostRequestAsync(requestStream, "/buffered", body, includeContentLength: true);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(1, handler.BufferedCalls);
        Assert.Equal(body, handler.BufferedBody);
    }

    [Fact]
    public async Task StreamingCapableHandler_BufferedFallback_OwnsSingleSegmentBody()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(777);
        DuplexStreamingHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WritePostRequestAsync(requestStream, "/buffered", body, includeContentLength: true);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(body, handler.BufferedBody);
        Assert.Equal(body.Length, handler.BufferedBodyBackingArrayLength);
    }

    [Fact]
    public async Task SequentialStreamingHandler_HashesLargeBodyWithoutRetainingChunks()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes((256 * 1024) + 17);
        SequentialHashStreamingHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WritePostRequestAsync(requestStream, "/hash", body, includeContentLength: true);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(System.Security.Cryptography.SHA256.HashData(body), response.Body);
        Assert.Equal(1, handler.StreamingCalls);
    }

    [Fact]
    public async Task StreamingCapableHandler_HandlesConcurrentBodylessRequests()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        const int RequestCount = 32;
        BodylessStreamingFallbackHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        Task<Http3Response>[] responseTasks = Enumerable.Range(0, RequestCount)
            .Select(async requestIndex =>
            {
                await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                await WriteGetRequestAsync(requestStream, $"/bodyless?request={requestIndex}");
                return await ReadResponseAsync(requestStream);
            })
            .ToArray();

        Http3Response[] responses = await Task.WhenAll(responseTasks).WaitAsync(TimeSpan.FromSeconds(20));

        Assert.All(responses, static response =>
        {
            Assert.Equal(200, response.StatusCode);
            Assert.Equal("bodyless", System.Text.Encoding.UTF8.GetString(response.Body));
            Assert.True(response.StreamCompleted);
        });
        Assert.Equal(RequestCount, handler.BufferedCalls);
    }

    [Fact]
    public async Task RequestDataBeforeHeaders_ClosesConnectionWithFrameUnexpected()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler(), diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] dataFrame = Http3FrameWriter.WriteData("before headers"u8);
        await requestStream.WriteAsync(dataFrame, 0, dataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection, diagnostics);

        Assert.Equal((ulong)Http3ErrorCode.FrameUnexpected, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, Http3ErrorCode.FrameUnexpected);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S4-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RequestDuplicatePseudoHeader_ClosesConnectionWithMessageError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler());
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] encoded = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":method", "POST"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", "/duplicate-pseudo-header"),
        ]);
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(encoded);
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)Http3ErrorCode.MessageError, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, Http3ErrorCode.MessageError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S4-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RequestCancelPushFrame_ClosesConnectionWithFrameUnexpectedBeforePayloadParsing()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler(), diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] cancelPushFrame = Http3FrameWriter.WriteFrame((ulong)Http3FrameType.CancelPush, []);
        await requestStream.WriteAsync(cancelPushFrame, 0, cancelPushFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection, diagnostics);

        Assert.Equal((ulong)Http3ErrorCode.FrameUnexpected, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, Http3ErrorCode.FrameUnexpected);
    }

    [Fact]
    public async Task PostDataRequest_WithContentLengthAndCoalescedData_DeliversBodyToHandler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = "playwright upload body"u8.ToArray();
        CaptureBodyHandler handler = new();
        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler, diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[][] bodyChunks = body.Chunk(16 * 1024).Select(static chunk => chunk.ToArray()).ToArray();
        await WritePostRequestDataFramesAsync(requestStream, "/upload", bodyChunks);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.True(
            response.StatusCode == 200,
            string.Join(" | ", diagnostics.Events.Select(static diagnostic => $"{diagnostic.Kind}:{diagnostic.ErrorCode}:{diagnostic.Message}")));
        Assert.Equal("playwright upload body", System.Text.Encoding.UTF8.GetString(handler.Body));
        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameReceived
                && diagnostic.FrameType == Http3FrameType.Data
                && diagnostic.PayloadLength == body.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task PostDataRequest_WithOneMegabyteBody_DeliversBodyToHandler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(1024 * 1024);
        CaptureBodyHandler handler = new();
        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler, diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[][] bodyChunks = body.Chunk(16 * 1024).Select(static chunk => chunk.ToArray()).ToArray();
        await WritePostRequestDataFramesAsync(requestStream, "/upload", bodyChunks);

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.True(
            response.StatusCode == 200,
            string.Join(" | ", diagnostics.Events.Select(static diagnostic => $"{diagnostic.Kind}:{diagnostic.ErrorCode}:{diagnostic.Message}")));
        Assert.Equal(body.Length, handler.Body.Length);
        Assert.Equal(body, handler.Body);
        Assert.True(response.StreamCompleted);
        Assert.Equal(
            body.Length,
            diagnostics.Events
                .Where(static diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameReceived
                    && diagnostic.FrameType == Http3FrameType.Data)
                .Sum(static diagnostic => diagnostic.PayloadLength));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PostDataRequest_WithIncompleteContentLength_ClosesConnectionWithMessageError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        CaptureBodyHandler handler = new();
        await using TestServerContext context = await TestServerContext.StartAsync(handler, diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WritePostRequestAsync(
            requestStream,
            "/upload",
            "short"u8.ToArray(),
            declaredContentLength: 22,
            includeContentLength: true,
            coalesceHeadersAndData: true);

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection, diagnostics);

        Assert.Equal((ulong)Http3ErrorCode.MessageError, terminalState.Close.ApplicationErrorCode);
        await AssertPeerConnectionClosedAsync(connection, Http3ErrorCode.MessageError);
        Assert.Empty(handler.Body);
        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.Error
                && diagnostic.ErrorCode == nameof(Http3ErrorCode.MessageError));
    }

    [Fact]
    public async Task TruncatedRequestFrame_ClosesConnectionWithFrameError()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler(), diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] truncatedHeadersFrame = [0x01, 0x05, 0x00, 0x00];
        await requestStream.WriteAsync(truncatedHeadersFrame, 0, truncatedHeadersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnectionTerminalState terminalState = await WaitForConnectionCloseAsync(connection);

        Assert.Equal((ulong)Http3ErrorCode.FrameError, terminalState.Close.ApplicationErrorCode);
        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.Error
                && diagnostic.ErrorCode == nameof(Http3ErrorCode.FrameError));
    }

    [Fact]
    public async Task StreamingResponse_WritesAsyncDataFramesToResponseBody()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new StreamingBodyHandler());

        Http3Response response = await context.GetAsync("/stream");

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("line 1\nline 2\n", System.Text.Encoding.UTF8.GetString(response.Body));
        Assert.True(response.StreamCompleted);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S6-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task PeerControlStream_BundledSettingsFrame_IsObserved()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/hello", "hello"),
            diagnostics);
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        await OpenClientUnidirectionalStreamsAsync(connection);
        await WaitForDiagnosticAsync(
            diagnostics,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.SettingsReceived
                && diagnostic.StreamId == 2
                && diagnostic.Role == "server");

        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.StreamOpened
                && diagnostic.StreamId == 2
                && diagnostic.StreamKind == Http3StreamKind.Control);
    }

    [Fact]
    public async Task DiagnosticsDisabled_SuppressesEventsAndPreservesRequestResponseBehavior()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        SwitchableHttp3DiagnosticsSink diagnostics = new(enabled: false);
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/hello", "hello from disabled diagnostics"),
            diagnostics);

        Http3Response response = await context.GetAsync("/hello");

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("hello from disabled diagnostics", System.Text.Encoding.UTF8.GetString(response.Body));
        Assert.Empty(diagnostics.Events);
        Assert.Equal(0, diagnostics.EmitCalls);
        Assert.True(diagnostics.IsEnabledCalls > 0);
    }

    [Fact]
    public void DiagnosticsDisabled_HelperSuppressesStreamFrameAndLifecycleEvents()
    {
        SwitchableHttp3DiagnosticsSink diagnostics = new(enabled: false);

        Http3Server.EmitStreamOpenedDiagnostic(diagnostics, "server", 4, Http3StreamKind.Request);
        Http3Server.EmitFrameDiagnostic(diagnostics, Http3DiagnosticKind.FrameReceived, "server", 4, Http3FrameType.Headers, 16);
        Http3Server.EmitRequestStartedDiagnostic(diagnostics, "server", 4, "GET", "/plaintext");
        Http3Server.EmitResponseStartedDiagnostic(diagnostics, "server", 4, 200);
        Http3Server.EmitResponseCompletedDiagnostic(diagnostics, "server", 4, 200, 13);
        Http3Server.EmitRequestCompletedDiagnostic(diagnostics, "server", 4, "GET", "/plaintext", 200, 13);
        Http3Server.EmitStreamClosedDiagnostic(diagnostics, "server", 4, Http3StreamKind.Request);

        Assert.Empty(diagnostics.Events);
        Assert.Equal(0, diagnostics.EmitCalls);
        Assert.Equal(7, diagnostics.IsEnabledCalls);
    }

    [Fact]
    public void DiagnosticsEnabled_HelperPreservesEventPayloadsAndOrdering()
    {
        SwitchableHttp3DiagnosticsSink diagnostics = new(enabled: true);

        Http3Server.EmitStreamOpenedDiagnostic(diagnostics, "server", 4, Http3StreamKind.Request);
        Http3Server.EmitFrameDiagnostic(diagnostics, Http3DiagnosticKind.FrameReceived, "server", 4, Http3FrameType.Headers, 16);
        Http3Server.EmitRequestStartedDiagnostic(diagnostics, "server", 4, "GET", "/plaintext");
        Http3Server.EmitResponseStartedDiagnostic(diagnostics, "server", 4, 200);
        Http3Server.EmitFrameDiagnostic(diagnostics, Http3DiagnosticKind.FrameSent, "server", 4, Http3FrameType.Data, 13);
        Http3Server.EmitResponseCompletedDiagnostic(diagnostics, "server", 4, 200, 13);
        Http3Server.EmitRequestCompletedDiagnostic(diagnostics, "server", 4, "GET", "/plaintext", 200, 13);
        Http3Server.EmitStreamClosedDiagnostic(diagnostics, "server", 4, Http3StreamKind.Request);

        Assert.Collection(
            diagnostics.Events,
            diagnostic =>
            {
                Assert.Equal(Http3DiagnosticKind.StreamOpened, diagnostic.Kind);
                Assert.Equal("server", diagnostic.Role);
                Assert.Equal(4, diagnostic.StreamId);
                Assert.Equal(Http3StreamKind.Request, diagnostic.StreamKind);
            },
            diagnostic =>
            {
                Assert.Equal(Http3DiagnosticKind.FrameReceived, diagnostic.Kind);
                Assert.Equal(Http3FrameType.Headers, diagnostic.FrameType);
                Assert.Equal((ulong)Http3FrameType.Headers, diagnostic.RawFrameType);
                Assert.Equal(16, diagnostic.PayloadLength);
            },
            diagnostic =>
            {
                Assert.Equal(Http3DiagnosticKind.RequestStarted, diagnostic.Kind);
                Assert.Equal("GET", diagnostic.Method);
                Assert.Equal("/plaintext", diagnostic.Path);
            },
            diagnostic =>
            {
                Assert.Equal(Http3DiagnosticKind.ResponseStarted, diagnostic.Kind);
                Assert.Equal(200, diagnostic.StatusCode);
            },
            diagnostic =>
            {
                Assert.Equal(Http3DiagnosticKind.FrameSent, diagnostic.Kind);
                Assert.Equal(Http3FrameType.Data, diagnostic.FrameType);
                Assert.Equal(13, diagnostic.PayloadLength);
            },
            diagnostic =>
            {
                Assert.Equal(Http3DiagnosticKind.ResponseCompleted, diagnostic.Kind);
                Assert.Equal(200, diagnostic.StatusCode);
                Assert.Equal(13, diagnostic.PayloadLength);
            },
            diagnostic =>
            {
                Assert.Equal(Http3DiagnosticKind.RequestCompleted, diagnostic.Kind);
                Assert.Equal("GET", diagnostic.Method);
                Assert.Equal("/plaintext", diagnostic.Path);
                Assert.Equal(200, diagnostic.StatusCode);
                Assert.Equal(13, diagnostic.PayloadLength);
            },
            diagnostic =>
            {
                Assert.Equal(Http3DiagnosticKind.StreamClosed, diagnostic.Kind);
                Assert.Equal(Http3StreamKind.Request, diagnostic.StreamKind);
            });
        Assert.Equal(8, diagnostics.EmitCalls);
        Assert.Equal(8, diagnostics.IsEnabledCalls);
    }

    [Fact]
    public void DiagnosticsEnabled_LifecycleFastPathAvoidsGeneralDiagnosticEventEmission()
    {
        FastPathLifecycleDiagnosticsSink diagnostics = new(enabled: true);

        Http3Server.EmitRequestStartedDiagnostic(diagnostics, "server", 4, "GET", "/plaintext");
        Http3Server.EmitResponseStartedDiagnostic(diagnostics, "server", 4, 200);
        Http3Server.EmitResponseCompletedDiagnostic(diagnostics, "server", 4, 200, 13);
        Http3Server.EmitRequestCompletedDiagnostic(diagnostics, "server", 4, "GET", "/plaintext", 200, 13);

        Assert.Equal(0, diagnostics.EmitCalls);
        Assert.Equal(4, diagnostics.IsEnabledCalls);
        Assert.Equal(1, diagnostics.RequestStartedCalls);
        Assert.Equal(1, diagnostics.ResponseStartedCalls);
        Assert.Equal(1, diagnostics.ResponseCompletedCalls);
        Assert.Equal(1, diagnostics.RequestCompletedCalls);
        Assert.Equal("/plaintext", diagnostics.LastPath);
        Assert.Equal(200, diagnostics.LastStatusCode);
        Assert.Equal(13, diagnostics.LastPayloadLength);
    }

    [Fact]
    public void DiagnosticsEnabled_KindFilterSuppressesUnwantedEventKinds()
    {
        FilteredLifecycleDiagnosticsSink diagnostics = new(
            enabled: true,
            Http3DiagnosticKind.RequestStarted,
            Http3DiagnosticKind.RequestCompleted);

        Http3Server.EmitFrameDiagnostic(diagnostics, Http3DiagnosticKind.FrameSent, "server", 4, Http3FrameType.Data, 13);
        Http3Server.EmitRequestStartedDiagnostic(diagnostics, "server", 4, "GET", "/plaintext");
        Http3Server.EmitResponseCompletedDiagnostic(diagnostics, "server", 4, 200, 13);
        Http3Server.EmitRequestCompletedDiagnostic(diagnostics, "server", 4, "GET", "/plaintext", 200, 13);

        Assert.Equal(0, diagnostics.EmitCalls);
        Assert.Equal(4, diagnostics.IsEnabledCalls);
        Assert.Equal(4, diagnostics.KindEnabledCalls);
        Assert.Equal(1, diagnostics.RequestStartedCalls);
        Assert.Equal(0, diagnostics.ResponseCompletedCalls);
        Assert.Equal(1, diagnostics.RequestCompletedCalls);
    }

    [Fact]
    public async Task DiagnosticsEnabled_SimpleRequestLifecyclePayloadsAndOrderingStayStable()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        RecordingHttp3DiagnosticsSink diagnostics = new();
        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/hello", "hello diagnostics"),
            diagnostics);

        Http3Response response = await context.GetAsync("/hello");
        await WaitForDiagnosticAsync(
            diagnostics,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.RequestCompleted
                && diagnostic.Path == "/hello"
                && diagnostic.StatusCode == 200);

        Assert.Equal(200, response.StatusCode);
        Http3DiagnosticEvent[] events = diagnostics.Events;
        Http3DiagnosticEvent requestStarted = Assert.Single(
            events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.RequestStarted
                && diagnostic.Path == "/hello");
        long streamId = requestStarted.StreamId ?? throw new InvalidOperationException("Request diagnostic did not carry a stream id.");
        Http3DiagnosticEvent[] streamEvents = events
            .Where(diagnostic => diagnostic.StreamId == streamId)
            .ToArray();

        Assert.Contains(
            streamEvents,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.StreamOpened
                && diagnostic.Role == "server"
                && diagnostic.StreamKind == Http3StreamKind.Request);
        Assert.Contains(
            streamEvents,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameReceived
                && diagnostic.FrameType == Http3FrameType.Headers
                && diagnostic.PayloadLength > 0);
        Assert.Contains(
            streamEvents,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameSent
                && diagnostic.FrameType == Http3FrameType.Headers
                && diagnostic.PayloadLength > 0);
        Assert.Contains(
            streamEvents,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameSent
                && diagnostic.FrameType == Http3FrameType.Data
                && diagnostic.PayloadLength == response.Body.Length);

        AssertDiagnosticOrder(streamEvents, Http3DiagnosticKind.RequestStarted, Http3DiagnosticKind.ResponseStarted);
        AssertDiagnosticOrder(streamEvents, Http3DiagnosticKind.ResponseStarted, Http3DiagnosticKind.ResponseCompleted);
        AssertDiagnosticOrder(streamEvents, Http3DiagnosticKind.ResponseCompleted, Http3DiagnosticKind.RequestCompleted);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task AbruptStreamReset_DoesNotStopLaterRequest()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(
            new Http3InMemoryRouteHandler().MapGetText("/after-reset", "still alive"));
        await using (QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10)))
        {
            await OpenClientUnidirectionalStreamsAsync(connection);
            QuicStream resetStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            resetStream.Abort(QuicAbortDirection.Write, 0);
            await resetStream.DisposeAsync();
        }

        await Task.Delay(TimeSpan.FromMilliseconds(200));
        Assert.False(context.ServerTask.IsCompleted);
    }

    private static async Task OpenClientUnidirectionalStreamsAsync(QuicConnection connection)
    {
        await OpenClientUnidirectionalStreamsAsync(connection, new Http3Settings(), []);
    }

    private static async Task OpenClientUnidirectionalStreamsAsync(
        QuicConnection connection,
        Http3Settings settings,
        IEnumerable<byte[]> encoderInstructions)
    {
        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] settingsBytes = Http3SettingsWriter.WriteInitialControlStream(settings);
        await controlStream.WriteAsync(settingsBytes, 0, settingsBytes.Length).WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream encoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteStreamTypeAsync(encoderStream, Http3StreamType.QPackEncoder);
        foreach (byte[] instruction in encoderInstructions)
        {
            await encoderStream.WriteAsync(instruction, 0, instruction.Length).WaitAsync(TimeSpan.FromSeconds(10));
        }

        QuicStream decoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteStreamTypeAsync(decoderStream, Http3StreamType.QPackDecoder);
    }

    private static async Task WriteGetRequestAsync(QuicStream requestStream, string path)
    {
        await WriteGetRequestHeadersAsync(requestStream, path);
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task WriteFragmentedGetRequestAsync(QuicStream requestStream, string path)
    {
        byte[] encoded = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", path),
        ]);
        byte[] frame = Http3FrameWriter.WriteHeaders(encoded);
        int split = Math.Max(1, frame.Length / 2);
        await requestStream.WriteAsync(frame, 0, split).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.WriteAsync(frame, split, frame.Length - split).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task WritePostRequestAsync(
        QuicStream requestStream,
        string path,
        byte[] body,
        bool includeContentLength = false,
        bool coalesceHeadersAndData = false,
        int? declaredContentLength = null)
    {
        List<QPackFieldLine> fields =
        [
            new QPackFieldLine(":method", "POST"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", path),
        ];
        if (includeContentLength)
        {
            fields.Add(new QPackFieldLine("content-length", (declaredContentLength ?? body.Length).ToString(System.Globalization.CultureInfo.InvariantCulture)));
            fields.Add(new QPackFieldLine("content-type", "text/plain"));
        }

        byte[] encoded = QPackEncoder.EncodeFieldSection(fields);
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(encoded);
        byte[] dataFrame = Http3FrameWriter.WriteData(body);
        if (coalesceHeadersAndData)
        {
            byte[] requestBytes = new byte[headersFrame.Length + dataFrame.Length];
            headersFrame.CopyTo(requestBytes, 0);
            dataFrame.CopyTo(requestBytes, headersFrame.Length);
            await requestStream.WriteAsync(requestBytes, 0, requestBytes.Length).WaitAsync(TimeSpan.FromSeconds(10));
        }
        else
        {
            await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
            await requestStream.WriteAsync(dataFrame, 0, dataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        }

        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static byte[] CreateDeterministicBytes(int size)
    {
        byte[] bytes = new byte[size];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(index % 251);
        }

        return bytes;
    }

    private static async Task WritePostRequestDataFramesAsync(
        QuicStream requestStream,
        string path,
        IReadOnlyList<byte[]> bodyChunks)
    {
        int contentLength = bodyChunks.Sum(static chunk => chunk.Length);
        List<QPackFieldLine> fields =
        [
            new QPackFieldLine(":method", "POST"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", path),
            new QPackFieldLine("content-length", contentLength.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new QPackFieldLine("content-type", "text/plain"),
        ];

        byte[] headersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(fields));
        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        foreach (byte[] chunk in bodyChunks)
        {
            byte[] dataFrame = Http3FrameWriter.WriteData(chunk);
            await requestStream.WriteAsync(dataFrame, 0, dataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        }

        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task WriteFragmentedPostRequestAsync(QuicStream requestStream, string path, byte[] body)
    {
        List<QPackFieldLine> fields =
        [
            new QPackFieldLine(":method", "POST"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", path),
            new QPackFieldLine("content-length", body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new QPackFieldLine("content-type", "text/plain"),
        ];
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(QPackEncoder.EncodeFieldSection(fields));
        byte[] dataFrame = Http3FrameWriter.WriteData(body);
        byte[] requestBytes = new byte[headersFrame.Length + dataFrame.Length];
        headersFrame.CopyTo(requestBytes, 0);
        dataFrame.CopyTo(requestBytes, headersFrame.Length);

        int split = Math.Max(1, requestBytes.Length / 3);
        await requestStream.WriteAsync(requestBytes, 0, split).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.WriteAsync(requestBytes, split, requestBytes.Length - split).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task WriteGetRequestHeadersAsync(QuicStream requestStream, string path)
    {
        byte[] encoded = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", path),
        ]);
        byte[] frame = Http3FrameWriter.WriteHeaders(encoded);
        await requestStream.WriteAsync(frame, 0, frame.Length).WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task WriteWebSocketConnectHeadersAsync(QuicStream requestStream, string path)
    {
        await WriteExtendedConnectHeadersAsync(requestStream, path, Http3ExtendedConnect.WebSocketProtocol);
    }

    private static async Task WriteExtendedConnectHeadersAsync(QuicStream requestStream, string path, string protocol)
    {
        byte[] encoded = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", protocol),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "localhost"),
            new QPackFieldLine(":path", path),
        ]);
        byte[] frame = Http3FrameWriter.WriteHeaders(encoded);
        await requestStream.WriteAsync(frame, 0, frame.Length).WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task<Http3Response> ReadResponseAsync(QuicStream stream)
    {
        Http3FrameReader reader = new();
        byte[] buffer = new byte[1024];
        QPackFieldLine[]? headers = null;
        List<byte> body = [];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            if (bytesRead == 0)
            {
                foreach (Http3Frame frame in reader.Complete())
                {
                    ProcessFrame(frame, ref headers, body);
                }

                break;
            }

            foreach (Http3Frame frame in reader.Read(buffer.AsSpan(0, bytesRead)))
            {
                ProcessFrame(frame, ref headers, body);
            }
        }

        Assert.NotNull(headers);
        QPackFieldLine status = Assert.Single(headers, header => header.Name == ":status");
        return new Http3Response(int.Parse(status.Value), headers, [.. body], streamCompleted: true);
    }

    private static async Task<QuicConnectionTerminalState> WaitForConnectionCloseAsync(
        QuicConnection connection,
        RecordingHttp3DiagnosticsSink? diagnostics = null)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(20);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (connection.Runtime.TerminalState is QuicConnectionTerminalState terminalState)
            {
                return terminalState;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(25));
        }

        string diagnosticSuffix = diagnostics is null
            ? string.Empty
            : $" Server diagnostics: {string.Join(
                " | ",
                diagnostics.Events.Select(static diagnostic => $"{diagnostic.Kind}:{diagnostic.StreamId}:{diagnostic.FrameType}:{diagnostic.ErrorCode}:{diagnostic.Message}"))}";
        throw new TimeoutException($"Timed out waiting for the peer HTTP/3 connection close.{diagnosticSuffix}");
    }

    private static async Task AssertPeerConnectionClosedAsync(QuicConnection connection, Http3ErrorCode expectedErrorCode)
        => await AssertPeerConnectionClosedAsync(connection, checked((long)expectedErrorCode));

    private static async Task AssertPeerConnectionClosedAsync(QuicConnection connection, QPackErrorCode expectedErrorCode)
        => await AssertPeerConnectionClosedAsync(connection, checked((long)expectedErrorCode));

    private static async Task AssertPeerConnectionClosedAsync(QuicConnection connection, long expectedErrorCode)
    {
        QuicException exception = await Assert.ThrowsAsync<QuicException>(async () =>
            await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(expectedErrorCode, exception.ApplicationErrorCode);
    }

    private static async Task<QPackFieldLine[]> ReadResponseHeadersAsync(QuicStream stream)
    {
        Http3FrameReader reader = new();
        byte[] buffer = new byte[1];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            Assert.NotEqual(0, bytesRead);
            foreach (Http3Frame frame in reader.Read(buffer.AsSpan(0, bytesRead)))
            {
                if (frame is Http3HeadersFrame headersFrame)
                {
                    return QPackDecoder.DecodeFieldSection(headersFrame.EncodedFieldSection);
                }
            }
        }
    }

    private static async Task<Http3WebSocketMessage> ReadOneWebSocketMessageAsync(
        QuicStream stream,
        Http3EndpointRole receivingEndpointRole)
    {
        Http3WebSocketMessageReader reader = new(receivingEndpointRole);
        byte[] buffer = new byte[1024];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            if (bytesRead == 0)
            {
                Http3WebSocketMessage[] completed = reader.Complete();
                return Assert.Single(completed);
            }

            Http3WebSocketMessage[] messages = reader.Read(buffer.AsSpan(0, bytesRead));
            if (messages.Length != 0)
            {
                return Assert.Single(messages);
            }
        }
    }

    private static async Task<Http3WebSocketMessage[]> ReadWebSocketMessagesAsync(
        QuicStream stream,
        Http3EndpointRole receivingEndpointRole)
    {
        Http3WebSocketMessageReader reader = new(receivingEndpointRole);
        byte[] buffer = new byte[1024];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            if (bytesRead == 0)
            {
                return reader.Complete();
            }

            Http3WebSocketMessage[] messages = reader.Read(buffer.AsSpan(0, bytesRead));
            if (messages.Length != 0)
            {
                return messages;
            }
        }
    }

    private static async Task<Http3WebSocketMessage> ReadUntilWebSocketMessageAsync(
        QuicStream stream,
        Func<Http3WebSocketMessage, bool> predicate,
        Http3EndpointRole receivingEndpointRole)
    {
        Http3WebSocketMessageReader reader = new(receivingEndpointRole);
        byte[] buffer = new byte[1024];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            Assert.NotEqual(0, bytesRead);
            foreach (Http3WebSocketMessage message in reader.Read(buffer.AsSpan(0, bytesRead)))
            {
                if (predicate(message))
                {
                    return message;
                }
            }
        }
    }

    private static void ProcessFrame(Http3Frame frame, ref QPackFieldLine[]? headers, List<byte> body)
    {
        switch (frame)
        {
            case Http3HeadersFrame headersFrame:
                headers = QPackDecoder.DecodeFieldSection(headersFrame.EncodedFieldSection);
                break;
            case Http3DataFrame dataFrame:
                body.AddRange(dataFrame.Data.ToArray());
                break;
        }
    }

    private static async Task WriteStreamTypeAsync(QuicStream stream, Http3StreamType streamType)
    {
        Span<byte> destination = stackalloc byte[Http3VariableLengthInteger.MaxEncodedLength];
        Assert.True(Http3VariableLengthInteger.TryFormat(checked((ulong)streamType), destination, out int bytesWritten));
        byte[] encoded = destination[..bytesWritten].ToArray();
        await stream.WriteAsync(encoded, 0, encoded.Length).WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task WaitForDiagnosticAsync(
        RecordingHttp3DiagnosticsSink diagnostics,
        Predicate<Http3DiagnosticEvent> predicate)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(10));
        while (!timeout.IsCancellationRequested)
        {
            if (diagnostics.Events.Any(diagnostic => predicate(diagnostic)))
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(25), timeout.Token);
        }

        Assert.Fail("The expected HTTP/3 diagnostic event was not observed.");
    }

    private static void AssertDiagnosticOrder(
        IReadOnlyList<Http3DiagnosticEvent> diagnostics,
        Http3DiagnosticKind before,
        Http3DiagnosticKind after)
    {
        int beforeIndex = -1;
        int afterIndex = -1;
        for (int index = 0; index < diagnostics.Count; index++)
        {
            if (beforeIndex < 0 && diagnostics[index].Kind == before)
            {
                beforeIndex = index;
            }

            if (afterIndex < 0 && diagnostics[index].Kind == after)
            {
                afterIndex = index;
            }
        }

        Assert.True(beforeIndex >= 0, $"Missing diagnostic kind {before}.");
        Assert.True(afterIndex >= 0, $"Missing diagnostic kind {after}.");
        Assert.True(beforeIndex < afterIndex, $"{before} should be emitted before {after}.");
    }

    private sealed class TestServerContext : IAsyncDisposable
    {
        private readonly Http3Server server;
        private readonly CancellationTokenSource cancellation = new();
        private readonly Task serverTask;
        private readonly X509Certificate2 serverCertificate;

        private TestServerContext(Http3Server server, IPEndPoint endpoint, X509Certificate2 serverCertificate)
        {
            this.server = server;
            Endpoint = endpoint;
            this.serverCertificate = serverCertificate;
            serverTask = server.ServeAsync(cancellation.Token);
        }

        internal IPEndPoint Endpoint { get; }

        internal Task ServerTask => serverTask;

        internal static async ValueTask<TestServerContext> StartAsync(
            IHttp3RequestHandler handler,
            IHttp3DiagnosticsSink? diagnosticsSink = null,
            Action<QuicServerConnectionOptions>? configureServerOptions = null,
            Action<Http3ServerOptions>? configureHttp3Options = null)
        {
            X509Certificate2 certificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(certificate);
            configureServerOptions?.Invoke(serverOptions);
            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = listenEndPoint,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ListenBacklog = 1,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
            };
            Http3ServerOptions http3Options = new()
            {
                DiagnosticsSink = diagnosticsSink,
            };
            configureHttp3Options?.Invoke(http3Options);

            Http3Server server = await Http3Server.ListenAsync(
                listenerOptions,
                handler,
                http3Options).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            return new TestServerContext(server, listenEndPoint, certificate);
        }

        internal QuicClientConnectionOptions CreateClientOptions()
        {
            QuicClientConnectionOptions options = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                new IPEndPoint(IPAddress.Loopback, Endpoint.Port),
                targetHost: "localhost",
                trustedServerCertificate: serverCertificate);
            options.MaxInboundUnidirectionalStreams = 3;
            return options;
        }

        internal async ValueTask<Http3Response> GetAsync(
            string path,
            bool completeOnContentLength = false,
            IHttp3DiagnosticsSink? diagnosticsSink = null)
        {
            return await Http3Client.GetAsync(
                CreateClientOptions(),
                new Uri($"https://localhost:{Endpoint.Port}{path}"),
                new Http3ClientOptions
                {
                    CompleteResponseOnContentLength = completeOnContentLength,
                    DiagnosticsSink = diagnosticsSink,
                }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
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

    private sealed class RecordingHttp3DiagnosticsSink : IHttp3DiagnosticsSink
    {
        private readonly List<Http3DiagnosticEvent> events = [];

        public bool IsEnabled => true;

        internal Http3DiagnosticEvent[] Events
        {
            get
            {
                lock (events)
                {
                    return [.. events];
                }
            }
        }

        public void Emit(Http3DiagnosticEvent diagnosticEvent)
        {
            lock (events)
            {
                events.Add(diagnosticEvent);
            }
        }
    }

    private sealed class SwitchableHttp3DiagnosticsSink(bool enabled) : IHttp3DiagnosticsSink
    {
        private readonly List<Http3DiagnosticEvent> events = [];
        private int emitCalls;
        private int isEnabledCalls;

        public bool IsEnabled
        {
            get
            {
                Interlocked.Increment(ref isEnabledCalls);
                return enabled;
            }
        }

        internal int EmitCalls => Volatile.Read(ref emitCalls);

        internal int IsEnabledCalls => Volatile.Read(ref isEnabledCalls);

        internal Http3DiagnosticEvent[] Events
        {
            get
            {
                lock (events)
                {
                    return [.. events];
                }
            }
        }

        public void Emit(Http3DiagnosticEvent diagnosticEvent)
        {
            Interlocked.Increment(ref emitCalls);
            lock (events)
            {
                events.Add(diagnosticEvent);
            }
        }
    }

    private sealed class FastPathLifecycleDiagnosticsSink(bool enabled) : IHttp3LifecycleDiagnosticsSink
    {
        private int emitCalls;
        private int isEnabledCalls;

        public bool IsEnabled
        {
            get
            {
                Interlocked.Increment(ref isEnabledCalls);
                return enabled;
            }
        }

        internal int EmitCalls => Volatile.Read(ref emitCalls);

        internal int IsEnabledCalls => Volatile.Read(ref isEnabledCalls);

        internal int RequestStartedCalls { get; private set; }

        internal int ResponseStartedCalls { get; private set; }

        internal int ResponseCompletedCalls { get; private set; }

        internal int RequestCompletedCalls { get; private set; }

        internal string? LastPath { get; private set; }

        internal int LastStatusCode { get; private set; }

        internal int LastPayloadLength { get; private set; }

        public void Emit(Http3DiagnosticEvent diagnosticEvent)
        {
            _ = diagnosticEvent;
            Interlocked.Increment(ref emitCalls);
        }

        public void EmitRequestStarted(string role, long streamId, string method, string path)
        {
            _ = role;
            _ = streamId;
            _ = method;
            RequestStartedCalls++;
            LastPath = path;
        }

        public void EmitResponseStarted(string role, long streamId, int statusCode)
        {
            _ = role;
            _ = streamId;
            ResponseStartedCalls++;
            LastStatusCode = statusCode;
        }

        public void EmitResponseCompleted(string role, long streamId, int statusCode, int payloadLength)
        {
            _ = role;
            _ = streamId;
            ResponseCompletedCalls++;
            LastStatusCode = statusCode;
            LastPayloadLength = payloadLength;
        }

        public void EmitRequestCompleted(string role, long streamId, string method, string path, int statusCode, int payloadLength)
        {
            _ = role;
            _ = streamId;
            _ = method;
            RequestCompletedCalls++;
            LastPath = path;
            LastStatusCode = statusCode;
            LastPayloadLength = payloadLength;
        }
    }

    private sealed class FilteredLifecycleDiagnosticsSink : IHttp3LifecycleDiagnosticsSink, IHttp3DiagnosticKindFilter
    {
        private readonly HashSet<Http3DiagnosticKind> enabledKinds;
        private readonly bool enabled;
        private int emitCalls;
        private int isEnabledCalls;
        private int kindEnabledCalls;

        internal FilteredLifecycleDiagnosticsSink(bool enabled, params Http3DiagnosticKind[] enabledKinds)
        {
            this.enabled = enabled;
            this.enabledKinds = [.. enabledKinds];
        }

        public bool IsEnabled
        {
            get
            {
                Interlocked.Increment(ref isEnabledCalls);
                return enabled;
            }
        }

        internal int EmitCalls => Volatile.Read(ref emitCalls);

        internal int IsEnabledCalls => Volatile.Read(ref isEnabledCalls);

        internal int KindEnabledCalls => Volatile.Read(ref kindEnabledCalls);

        internal int RequestStartedCalls { get; private set; }

        internal int ResponseCompletedCalls { get; private set; }

        internal int RequestCompletedCalls { get; private set; }

        public bool IsEnabledFor(Http3DiagnosticKind kind)
        {
            Interlocked.Increment(ref kindEnabledCalls);
            return enabledKinds.Contains(kind);
        }

        public void Emit(Http3DiagnosticEvent diagnosticEvent)
        {
            _ = diagnosticEvent;
            Interlocked.Increment(ref emitCalls);
        }

        public void EmitRequestStarted(string role, long streamId, string method, string path)
        {
            _ = role;
            _ = streamId;
            _ = method;
            _ = path;
            RequestStartedCalls++;
        }

        public void EmitResponseStarted(string role, long streamId, int statusCode)
        {
            _ = role;
            _ = streamId;
            _ = statusCode;
        }

        public void EmitResponseCompleted(string role, long streamId, int statusCode, int payloadLength)
        {
            _ = role;
            _ = streamId;
            _ = statusCode;
            _ = payloadLength;
            ResponseCompletedCalls++;
        }

        public void EmitRequestCompleted(string role, long streamId, string method, string path, int statusCode, int payloadLength)
        {
            _ = role;
            _ = streamId;
            _ = method;
            _ = path;
            _ = statusCode;
            _ = payloadLength;
            RequestCompletedCalls++;
        }
    }

    private sealed class CaptureBodyHandler : IHttp3RequestHandler
    {
        public byte[] Body { get; private set; } = [];

        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
        {
            Body = request.Body.ToArray();
            return ValueTask.FromResult(new Http3ServerResponse(200, "ok"u8.ToArray()));
        }
    }

    private sealed class FixedResponseHandler(Http3ServerResponse response) : IHttp3RequestHandler
    {
        public ValueTask<Http3ServerResponse> HandleAsync(
            Http3Request request,
            CancellationToken cancellationToken = default)
        {
            _ = request;
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(response);
        }
    }

    private sealed class DuplexStreamingHandler : IHttp3RequestHandler, IHttp3StreamingRequestHandler
    {
        public int BufferedCalls { get; private set; }

        public byte[] BufferedBody { get; private set; } = [];

        public int BufferedBodyBackingArrayLength { get; private set; }

        public int StreamingCalls { get; private set; }

        public bool RetainBodyChunks { get; init; } = true;

        public bool CanHandleStreaming(Http3StreamingRequest request)
            => request.Path == "/duplex";

        public bool RetainStreamingRequestBodyChunks(Http3StreamingRequest request)
            => RetainBodyChunks;

        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
        {
            BufferedCalls++;
            BufferedBody = request.Body.ToArray();
            Assert.True(MemoryMarshal.TryGetArray(request.Body, out ArraySegment<byte> segment));
            BufferedBodyBackingArrayLength = segment.Array!.Length;
            byte[] body = System.Text.Encoding.UTF8.GetBytes("buffered:" + System.Text.Encoding.UTF8.GetString(request.Body.Span));
            return ValueTask.FromResult(new Http3ServerResponse(200, body));
        }

        public ValueTask<Http3ServerResponse> HandleStreamingAsync(
            Http3StreamingRequest request,
            CancellationToken cancellationToken = default)
        {
            StreamingCalls++;
            string contentLength = request.Headers
                .First(static header => header.Name == "content-length")
                .Value;
            return ValueTask.FromResult(Http3ServerResponse.CreateStreaming(
                200,
                EchoAsync(request.Body, cancellationToken),
                [
                    new QPackFieldLine("content-type", "application/octet-stream"),
                    new QPackFieldLine("content-length", contentLength),
                ]));
        }

        private static async IAsyncEnumerable<ReadOnlyMemory<byte>> EchoAsync(
            IAsyncEnumerable<ReadOnlyMemory<byte>> requestBody,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (ReadOnlyMemory<byte> chunk in requestBody.WithCancellation(cancellationToken))
            {
                yield return chunk;
            }
        }
    }

    private sealed class SequentialHashStreamingHandler : IHttp3RequestHandler, IHttp3StreamingRequestHandler
    {
        public int StreamingCalls { get; private set; }

        public bool CanHandleStreaming(Http3StreamingRequest request)
            => request.Path == "/hash";

        public bool RetainStreamingRequestBodyChunks(Http3StreamingRequest request)
            => false;

        public ValueTask<Http3ServerResponse> HandleAsync(
            Http3Request request,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The hash request must use the streaming handler.");

        public async ValueTask<Http3ServerResponse> HandleStreamingAsync(
            Http3StreamingRequest request,
            CancellationToken cancellationToken = default)
        {
            StreamingCalls++;
            using System.Security.Cryptography.IncrementalHash hash =
                System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
            await foreach (ReadOnlyMemory<byte> chunk in request.Body.WithCancellation(cancellationToken))
            {
                hash.AppendData(chunk.Span);
            }

            return new Http3ServerResponse(200, hash.GetHashAndReset());
        }
    }

    private sealed class BodylessStreamingFallbackHandler : IHttp3RequestHandler, IHttp3StreamingRequestHandler
    {
        private int bufferedCalls;

        public int BufferedCalls => Volatile.Read(ref bufferedCalls);

        public bool CanHandleStreaming(Http3StreamingRequest request) => false;

        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
        {
            Assert.True(request.Body.IsEmpty);
            Interlocked.Increment(ref bufferedCalls);
            return ValueTask.FromResult(new Http3ServerResponse(200, "bodyless"u8.ToArray()));
        }

        public ValueTask<Http3ServerResponse> HandleStreamingAsync(
            Http3StreamingRequest request,
            CancellationToken cancellationToken = default) => throw new InvalidOperationException("The bodyless fallback handler must not select streaming.");
    }

    private sealed class CaptureRequestHandler : IHttp3RequestHandler
    {
        public string Method { get; private set; } = string.Empty;

        public string Path { get; private set; } = string.Empty;

        public byte[] Body { get; private set; } = [];

        public IReadOnlyList<QPackFieldLine> Headers { get; private set; } = [];

        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
        {
            Method = request.Method;
            Path = request.Path;
            Body = request.Body.ToArray();
            Headers = request.Headers;
            return ValueTask.FromResult(new Http3ServerResponse(200, "ok"u8.ToArray()));
        }
    }

    private sealed class HeadersOnlyFastPathHandler : IHttp3RequestHandler, IHttp3HeadersOnlyRequestHandler
    {
        private int headersOnlyCalls;
        private int fullRequestCalls;

        public int HeadersOnlyCalls => Volatile.Read(ref headersOnlyCalls);

        public int FullRequestCalls => Volatile.Read(ref fullRequestCalls);

        public string Method { get; private set; } = string.Empty;

        public string Path { get; private set; } = string.Empty;

        public IReadOnlyList<QPackFieldLine> Headers { get; private set; } = [];

        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
        {
            _ = request;
            _ = cancellationToken;
            Interlocked.Increment(ref fullRequestCalls);
            return ValueTask.FromResult(new Http3ServerResponse(500, "slow"u8.ToArray()));
        }

        public ValueTask<Http3ServerResponse> HandleHeadersOnlyAsync(
            Http3HeadersOnlyRequest request,
            CancellationToken cancellationToken = default)
        {
            _ = cancellationToken;
            Interlocked.Increment(ref headersOnlyCalls);
            Method = request.Method;
            Path = request.Path;
            Headers = request.Headers;
            return ValueTask.FromResult(new Http3ServerResponse(200, "fast"u8.ToArray()));
        }
    }

    private sealed class StreamingBodyHandler : IHttp3RequestHandler
    {
        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(Http3ServerResponse.CreateStreaming(
                200,
                CreateBody(cancellationToken)));
        }

        private static async IAsyncEnumerable<ReadOnlyMemory<byte>> CreateBody(
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            yield return "line 1\n"u8.ToArray();
            await Task.Delay(10, cancellationToken);
            yield return "line 2\n"u8.ToArray();
        }
    }

    private sealed class EchoWebSocketHandler : IHttp3WebSocketHandler
    {
        public string Path { get; private set; } = string.Empty;

        public byte[] Payload { get; private set; } = [];

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            Path = context.Request.Path;
            Http3WebSocketMessage message = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a message arrived.");
            Payload = message.Payload.ToArray();

            byte[] responsePayload = System.Text.Encoding.UTF8.GetBytes("echo:" + System.Text.Encoding.UTF8.GetString(message.Payload.Span));
            await context.WriteMessageAsync(message.Opcode, responsePayload, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await context.Stream.CompleteWritesAsync(cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private sealed class CloseEchoWebSocketHandler : IHttp3WebSocketHandler
    {
        public ushort? StatusCode { get; private set; }

        public string? Reason { get; private set; }

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            Http3WebSocketMessage closeMessage = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a close frame arrived.");
            Http3WebSocketCloseStatus status = Http3WebSocketCloseFrameParser.Parse(closeMessage);
            StatusCode = status.StatusCode;
            Reason = status.Reason;
            await context.EchoCloseAsync(closeMessage, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private sealed class PingPongWebSocketHandler : IHttp3WebSocketHandler
    {
        public bool ObservedPing { get; private set; }

        public byte[] Payload { get; private set; } = [];

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            Http3WebSocketMessage pingMessage = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a ping frame arrived.");
            ObservedPing = pingMessage.Opcode == Http3WebSocketOpcode.Ping;
            await context.EchoPingAsync(pingMessage, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

            Http3WebSocketMessage dataMessage = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a data frame arrived.");
            Payload = dataMessage.Payload.ToArray();
            byte[] responsePayload = System.Text.Encoding.UTF8.GetBytes("echo:" + System.Text.Encoding.UTF8.GetString(dataMessage.Payload.Span));
            await context.WriteMessageAsync(dataMessage.Opcode, responsePayload, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await context.Stream.CompleteWritesAsync(cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private sealed class ApplicationCloseWebSocketHandler : IHttp3WebSocketHandler
    {
        public byte[] Payload { get; private set; } = [];

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            Http3WebSocketMessage message = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a data frame arrived.");
            Payload = message.Payload.ToArray();
            await context.CloseAsync(1003, "unsupported", cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private sealed class ProtocolErrorCloseWebSocketHandler : IHttp3WebSocketHandler
    {
        private readonly TaskCompletionSource observedProtocolError = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool ObservedProtocolError { get; private set; }

        public Task ObservedProtocolErrorAsync => observedProtocolError.Task;

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                _ = await context.ReadMessageOrCloseOnProtocolErrorAsync(cancellationToken: cancellationToken)
                    .AsTask()
                    .WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch (Http3Exception exception) when (exception.ErrorCode == Http3ErrorCode.MessageError)
            {
                ObservedProtocolError = true;
                observedProtocolError.SetResult();
            }
        }
    }

    private sealed class ServerPingWebSocketHandler : IHttp3WebSocketHandler
    {
        public bool ObservedPong { get; private set; }

        public byte[] Payload { get; private set; } = [];

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            await context.PingAsync("server-check"u8.ToArray(), cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

            Http3WebSocketMessage pongMessage = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a pong frame arrived.");
            ObservedPong = pongMessage.Opcode == Http3WebSocketOpcode.Pong;

            Http3WebSocketMessage dataMessage = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a data frame arrived.");
            Payload = dataMessage.Payload.ToArray();
            byte[] responsePayload = System.Text.Encoding.UTF8.GetBytes("echo:" + System.Text.Encoding.UTF8.GetString(dataMessage.Payload.Span));
            await context.WriteMessageAsync(dataMessage.Opcode, responsePayload, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await context.Stream.CompleteWritesAsync(cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private sealed class LocalPeerProofWebSocketHandler : IHttp3WebSocketHandler
    {
        private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string Path { get; private set; } = string.Empty;

        public string RequestSubprotocols { get; private set; } = string.Empty;

        public bool ObservedPong { get; private set; }

        public bool ObservedClientPing { get; private set; }

        public byte[] TextPayload { get; private set; } = [];

        public int BinaryPayloadLength { get; private set; }

        public ushort? CloseStatusCode { get; private set; }

        public string? CloseReason { get; private set; }

        public Task CompletionAsync => completion.Task;

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                Path = context.Request.Path;
                RequestSubprotocols = Assert.Single(
                    context.Request.Headers,
                    header => header.Name == "sec-websocket-protocol").Value;

                await context.PingAsync("server-proof"u8.ToArray(), cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

                Http3WebSocketMessage pongMessage = await context.ReadMessageAsync(cancellationToken)
                    ?? throw new InvalidOperationException("The WebSocket tunnel ended before a pong frame arrived.");
                ObservedPong = pongMessage.Opcode == Http3WebSocketOpcode.Pong
                    && System.Text.Encoding.UTF8.GetString(pongMessage.Payload.Span) == "server-proof";

                Http3WebSocketMessage clientPingMessage = await context.ReadMessageAsync(cancellationToken)
                    ?? throw new InvalidOperationException("The WebSocket tunnel ended before a client ping frame arrived.");
                ObservedClientPing = clientPingMessage.Opcode == Http3WebSocketOpcode.Ping
                    && System.Text.Encoding.UTF8.GetString(clientPingMessage.Payload.Span) == "client-proof";
                await context.EchoPingAsync(clientPingMessage, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

                Http3WebSocketMessage textMessage = await context.ReadMessageAsync(cancellationToken)
                    ?? throw new InvalidOperationException("The WebSocket tunnel ended before a text frame arrived.");
                TextPayload = textMessage.Payload.ToArray();
                byte[] textResponsePayload = System.Text.Encoding.UTF8.GetBytes("echo:" + System.Text.Encoding.UTF8.GetString(textMessage.Payload.Span));
                await context.WriteMessageAsync(textMessage.Opcode, textResponsePayload, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

                Http3WebSocketMessage binaryMessage = await context.ReadMessageAsync(cancellationToken)
                    ?? throw new InvalidOperationException("The WebSocket tunnel ended before a binary frame arrived.");
                BinaryPayloadLength = binaryMessage.Payload.Length;
                await context.WriteMessageAsync(binaryMessage.Opcode, binaryMessage.Payload, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

                Http3WebSocketMessage closeMessage = await context.ReadMessageAsync(cancellationToken)
                    ?? throw new InvalidOperationException("The WebSocket tunnel ended before a close frame arrived.");
                Http3WebSocketCloseStatus closeStatus = Http3WebSocketCloseFrameParser.Parse(closeMessage);
                CloseStatusCode = closeStatus.StatusCode;
                CloseReason = closeStatus.Reason;
                await context.EchoCloseAsync(closeMessage, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                completion.SetResult();
            }
            catch (Exception exception)
            {
                completion.SetException(exception);
                throw;
            }
        }
    }

    private sealed class KeepAliveObservedWebSocketHandler : IHttp3WebSocketHandler
    {
        public bool ObservedPong { get; private set; }

        public byte[] Payload { get; private set; } = [];

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            Http3WebSocketMessage pongMessage = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a pong frame arrived.");
            ObservedPong = pongMessage.Opcode == Http3WebSocketOpcode.Pong;

            Http3WebSocketMessage dataMessage = await context.ReadMessageAsync(cancellationToken)
                ?? throw new InvalidOperationException("The WebSocket tunnel ended before a data frame arrived.");
            Payload = dataMessage.Payload.ToArray();
            byte[] responsePayload = System.Text.Encoding.UTF8.GetBytes("echo:" + System.Text.Encoding.UTF8.GetString(dataMessage.Payload.Span));
            await context.WriteMessageAsync(dataMessage.Opcode, responsePayload, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await context.Stream.CompleteWritesAsync(cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private sealed class TcpForwardingWebSocketHandler(
        IPEndPoint endpoint,
        Http3WebSocketTcpForwarderOptions? forwarderOptions = null) : IHttp3WebSocketHandler
    {
        private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool Completed { get; private set; }

        public Task CompletionAsync => completion.Task;

        public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                using TcpClient client = new();
                await client.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                await Http3WebSocketTcpForwarder.ForwardAsync(context, client.GetStream(), forwarderOptions, cancellationToken)
                    .AsTask()
                    .WaitAsync(TimeSpan.FromSeconds(10));
                Completed = true;
                completion.SetResult();
            }
            catch (Exception exception)
            {
                completion.SetException(exception);
                throw;
            }
        }
    }

    private sealed class TcpEchoServerContext : IAsyncDisposable
    {
        private readonly CancellationTokenSource cancellation = new();
        private readonly TcpListener listener;
        private readonly Task serverTask;
        private readonly TaskCompletionSource<byte[]> observedPayload = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly int expectedPayloadLength;
        private readonly Func<byte[], byte[]> responseFactory;

        private TcpEchoServerContext(TcpListener listener, int expectedPayloadLength, Func<byte[], byte[]> responseFactory)
        {
            this.listener = listener;
            this.expectedPayloadLength = expectedPayloadLength;
            this.responseFactory = responseFactory;
            Endpoint = (IPEndPoint)listener.LocalEndpoint;
            serverTask = RunAsync();
        }

        internal IPEndPoint Endpoint { get; }

        internal Task<byte[]> ObservedPayloadAsync => observedPayload.Task;

        internal static TcpEchoServerContext Start(int expectedPayloadLength)
        {
            return Start(
                expectedPayloadLength,
                payload => System.Text.Encoding.UTF8.GetBytes("tcp:" + System.Text.Encoding.UTF8.GetString(payload)));
        }

        internal static TcpEchoServerContext Start(int expectedPayloadLength, Func<byte[], byte[]> responseFactory)
        {
            TcpListener listener = new(IPAddress.Loopback, 0);
            listener.Start();
            return new TcpEchoServerContext(listener, expectedPayloadLength, responseFactory);
        }

        public async ValueTask DisposeAsync()
        {
            cancellation.Cancel();
            listener.Stop();
            await SuppressExpectedShutdownAsync(serverTask);
            cancellation.Dispose();
        }

        private async Task RunAsync()
        {
            using TcpClient client = await listener.AcceptTcpClientAsync(cancellation.Token);
            await using NetworkStream stream = client.GetStream();
            byte[] payload = new byte[expectedPayloadLength];
            int totalBytesRead = 0;
            while (totalBytesRead < expectedPayloadLength)
            {
                int bytesRead = await stream.ReadAsync(
                    payload.AsMemory(totalBytesRead, expectedPayloadLength - totalBytesRead),
                    cancellation.Token);
                if (bytesRead == 0)
                {
                    observedPayload.TrySetResult(payload.AsSpan(0, totalBytesRead).ToArray());
                    return;
                }

                totalBytesRead += bytesRead;
            }

            observedPayload.TrySetResult(payload);
            byte[] response = responseFactory(payload);
            await stream.WriteAsync(response, cancellation.Token);
            await stream.FlushAsync(cancellation.Token);

            byte[] drainBuffer = new byte[256];
            while (await stream.ReadAsync(drainBuffer, cancellation.Token) > 0)
            {
            }
        }

        private static async Task SuppressExpectedShutdownAsync(Task task)
        {
            try
            {
                await task.WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                GC.KeepAlive(exception);
            }
        }
    }

    private sealed class ThrowingWebSocketHandler : IHttp3WebSocketHandler
    {
        public bool ObservedDispatch { get; private set; }

        public ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
        {
            ObservedDispatch = true;
            throw new InvalidOperationException("Synthetic WebSocket handler failure.");
        }
    }
}
