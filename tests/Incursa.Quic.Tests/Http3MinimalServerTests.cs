// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(Http3LoopbackTestCollection.Name)]
public sealed class Http3MinimalServerTests
{
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
    public async Task MalformedRequestHeaders_Returns400()
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

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(400, response.StatusCode);
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
    public async Task RequestDataBeforeHeaders_Returns400()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        await using TestServerContext context = await TestServerContext.StartAsync(new CaptureBodyHandler());
        await using QuicConnection connection = await QuicConnection.ConnectAsync(context.CreateClientOptions()).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await OpenClientUnidirectionalStreamsAsync(connection);

        await using QuicStream requestStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] dataFrame = Http3FrameWriter.WriteData("before headers"u8);
        await requestStream.WriteAsync(dataFrame, 0, dataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await WriteGetRequestHeadersAsync(requestStream, "/upload");
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(400, response.StatusCode);
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
    public async Task PostDataRequest_WithIncompleteContentLength_Returns400()
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

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(400, response.StatusCode);
        Assert.True(response.StreamCompleted);
        Assert.Empty(handler.Body);
        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.Error
                && diagnostic.ErrorCode == nameof(Http3ErrorCode.MessageError));
    }

    [Fact]
    public async Task TruncatedRequestFrame_Returns400()
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

        Http3Response response = await ReadResponseAsync(requestStream);

        Assert.Equal(400, response.StatusCode);
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
            Action<QuicServerConnectionOptions>? configureServerOptions = null)
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

            Http3Server server = await Http3Server.ListenAsync(
                listenerOptions,
                handler,
                new Http3ServerOptions
                {
                    DiagnosticsSink = diagnosticsSink,
                }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
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

    private sealed class CaptureBodyHandler : IHttp3RequestHandler
    {
        public byte[] Body { get; private set; } = [];

        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
        {
            Body = request.Body.ToArray();
            return ValueTask.FromResult(new Http3ServerResponse(200, "ok"u8.ToArray()));
        }
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
}
