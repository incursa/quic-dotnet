// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(Http3LoopbackTestCollection.Name)]
public sealed class Http3MinimalClientTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task GetAsync_OverLoopbackQuic_ReturnsResponseHeadersAndBody()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        TaskCompletionSource<object?> clientCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task serverTask = RunMinimalServerAsync(listener, clientCompleted.Task);

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);

        await using Http3Client client = await Http3Client.ConnectAsync(
            clientOptions,
            new Http3ClientOptions { UserAgent = "incursa-http3-test" }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Http3Response response;
        try
        {
            response = await client.GetAsync(
                new Uri($"https://localhost:{listenEndPoint.Port}/resource?q=1")).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            clientCompleted.TrySetResult(null);
        }

        Assert.Equal(200, response.StatusCode);
        Assert.True(response.StreamCompleted);
        Assert.Equal("hello over h3", System.Text.Encoding.ASCII.GetString(response.Body));
        Assert.Contains(response.Headers, header => header.Name == "content-type" && header.Value == "text/plain");

        await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task GetAsync_WithExactContentLength_WaitsForStreamFinBeforeCompleting()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        };

        byte[] responseBody = "client must wait for stream fin"u8.ToArray();
        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        TaskCompletionSource<object?> responsePayloadSent = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<object?> responseFinAllowed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task serverTask = RunDelayedResponseFinServerAsync(
            listener,
            responseBody,
            responsePayloadSent,
            responseFinAllowed.Task);

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);
        RecordingHttp3DiagnosticsSink diagnostics = new();

        await using Http3Client client = await Http3Client.ConnectAsync(
            clientOptions,
            new Http3ClientOptions
            {
                CompleteResponseOnContentLength = true,
                DiagnosticsSink = diagnostics,
            }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<Http3Response> responseTask = client.GetAsync(
            new Uri($"https://localhost:{listenEndPoint.Port}/delayed-fin")).AsTask();

        await responsePayloadSent.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await WaitForDiagnosticAsync(
            diagnostics,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameReceived
                && diagnostic.FrameType == Http3FrameType.Data
                && diagnostic.PayloadLength == responseBody.Length);

        Task firstCompleted = await Task.WhenAny(responseTask, Task.Delay(TimeSpan.FromMilliseconds(500)));
        Assert.NotSame(responseTask, firstCompleted);
        Assert.DoesNotContain(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.ResponseCompleted);

        responseFinAllowed.TrySetResult(null);
        Http3Response response = await responseTask.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(200, response.StatusCode);
        Assert.True(response.StreamCompleted);
        Assert.Equal(responseBody, response.Body);
        Assert.Contains(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.ResponseCompleted
                && diagnostic.PayloadLength == responseBody.Length);

        await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S8-0001")]
    [Requirement("REQ-QUIC-RFC9114-S9-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task GetAsync_WithShortResponseBodyAndFin_RejectsContentLengthMismatch()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        };

        byte[] responseBody = "short response body"u8.ToArray();
        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        TaskCompletionSource<object?> responsePayloadSent = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<object?> responseFinAllowed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task serverTask = RunDelayedResponseFinServerAsync(
            listener,
            responseBody,
            responsePayloadSent,
            responseFinAllowed.Task,
            declaredContentLength: checked((ulong)responseBody.Length + 1));

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);
        RecordingHttp3DiagnosticsSink diagnostics = new();

        await using Http3Client client = await Http3Client.ConnectAsync(
            clientOptions,
            new Http3ClientOptions { DiagnosticsSink = diagnostics }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        Task<Http3Response> responseTask = client.GetAsync(
            new Uri($"https://localhost:{listenEndPoint.Port}/delayed-fin")).AsTask();

        await responsePayloadSent.Task.WaitAsync(TimeSpan.FromSeconds(10));
        responseFinAllowed.TrySetResult(null);
        Http3Exception exception = await Assert.ThrowsAsync<Http3Exception>(
            async () => await responseTask.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.Contains("Content-Length", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(
            diagnostics.Events,
            diagnostic => diagnostic.Kind == Http3DiagnosticKind.ResponseCompleted);

        await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S6-0001")]
    [Requirement("REQ-QUIC-RFC9114-S7-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectAsync_ObservesPeerControlSettingsAndRejectsRequestsAfterGoAway()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        TaskCompletionSource<object?> clientCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task serverTask = RunGoAwayControlServerAsync(listener, clientCompleted.Task);

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            targetHost: "localhost",
            trustedServerCertificate: serverCertificate);
        RecordingHttp3DiagnosticsSink diagnostics = new();

        await using Http3Client client = await Http3Client.ConnectAsync(
            clientOptions,
            new Http3ClientOptions { DiagnosticsSink = diagnostics }).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        try
        {
            await WaitForDiagnosticAsync(
                diagnostics,
                diagnostic => diagnostic.Kind == Http3DiagnosticKind.SettingsReceived
                    && diagnostic.Role == "client");
            await WaitForDiagnosticAsync(
                diagnostics,
                diagnostic => diagnostic.Kind == Http3DiagnosticKind.FrameReceived
                    && diagnostic.Role == "client"
                    && diagnostic.FrameType == Http3FrameType.GoAway);

            Http3Exception exception = await Assert.ThrowsAsync<Http3Exception>(
                async () => await client.GetAsync(
                    new Uri($"https://localhost:{listenEndPoint.Port}/after-goaway")).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

            Assert.Equal(Http3ErrorCode.RequestRejected, exception.ErrorCode);
        }
        finally
        {
            clientCompleted.TrySetResult(null);
        }

        await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectAsync_RejectsClientOptionsWithoutH3Alpn()
    {
        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, 443));
        SslClientAuthenticationOptions? authenticationOptions = clientOptions.ClientAuthenticationOptions;
        if (authenticationOptions is null)
        {
            throw new InvalidOperationException("The test client options did not include TLS authentication options.");
        }

        authenticationOptions.ApplicationProtocols ??= [];
        authenticationOptions.ApplicationProtocols.Clear();
        authenticationOptions.ApplicationProtocols.Add(SslApplicationProtocol.Http11);

        ArgumentException exception = Assert.Throws<ArgumentException>(
            () => Http3Client.ConnectAsync(clientOptions).AsTask().GetAwaiter().GetResult());

        Assert.Contains("ALPN h3", exception.Message, StringComparison.Ordinal);
    }

    private static async Task RunMinimalServerAsync(QuicListener listener, Task clientCompleted)
    {
        await using QuicConnection connection = await listener.AcceptConnectionAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicStream? requestStream = null;
        List<QuicStream> unidirectionalStreams = [];

        try
        {
            while (requestStream is null || unidirectionalStreams.Count < 3)
            {
                QuicStream stream = await connection.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                if (stream.Type == QuicStreamType.Bidirectional)
                {
                    requestStream = stream;
                }
                else
                {
                    unidirectionalStreams.Add(stream);
                    await ObserveUnidirectionalStreamPreambleAsync(stream);
                }
            }

            Assert.NotNull(requestStream);
            await RespondAsync(requestStream);
            await clientCompleted.WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            if (requestStream is not null)
            {
                await requestStream.DisposeAsync();
            }

            foreach (QuicStream stream in unidirectionalStreams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    private static async Task RunGoAwayControlServerAsync(QuicListener listener, Task clientCompleted)
    {
        await using QuicConnection connection = await listener.AcceptConnectionAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        List<QuicStream> clientUnidirectionalStreams = [];
        QuicStream? serverControlStream = null;

        try
        {
            serverControlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            await WriteServerControlStreamWithGoAwayAsync(serverControlStream, goAwayStreamId: 0);

            while (clientUnidirectionalStreams.Count < 3)
            {
                QuicStream stream = await connection.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                if (stream.Type != QuicStreamType.Unidirectional)
                {
                    await stream.DisposeAsync();
                    continue;
                }

                clientUnidirectionalStreams.Add(stream);
                await ObserveUnidirectionalStreamPreambleAsync(stream);
            }

            await clientCompleted.WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally
        {
            if (serverControlStream is not null)
            {
                await serverControlStream.DisposeAsync();
            }

            foreach (QuicStream stream in clientUnidirectionalStreams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    private static async Task WriteServerControlStreamWithGoAwayAsync(
        QuicStream controlStream,
        ulong goAwayStreamId)
    {
        byte[] streamTypeBytes = EncodeVariableLengthInteger((ulong)Http3StreamType.Control);
        byte[] settingsFrame = Http3FrameWriter.WriteSettings(
        [
            new Http3Setting((ulong)Http3SettingIdentifier.QPackMaxTableCapacity, 0),
            new Http3Setting((ulong)Http3SettingIdentifier.QPackBlockedStreams, 0),
        ]);
        byte[] goAwayFrame = Http3FrameWriter.WriteGoAway(goAwayStreamId);
        byte[] controlPayload = [.. streamTypeBytes, .. settingsFrame, .. goAwayFrame];

        await controlStream.WriteAsync(controlPayload, 0, controlPayload.Length).WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task RunDelayedResponseFinServerAsync(
        QuicListener listener,
        byte[] responseBody,
        TaskCompletionSource<object?> responsePayloadSent,
        Task responseFinAllowed,
        ulong? declaredContentLength = null)
    {
        await using QuicConnection connection = await listener.AcceptConnectionAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        QuicStream? requestStream = null;
        List<QuicStream> unidirectionalStreams = [];

        try
        {
            while (requestStream is null || unidirectionalStreams.Count < 3)
            {
                QuicStream stream = await connection.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
                if (stream.Type == QuicStreamType.Bidirectional)
                {
                    requestStream = stream;
                }
                else
                {
                    unidirectionalStreams.Add(stream);
                    await ObserveUnidirectionalStreamPreambleAsync(stream);
                }
            }

            Assert.NotNull(requestStream);
            QPackFieldLine[] requestHeaders = await ReadRequestHeadersAsync(requestStream);
            Assert.Contains(requestHeaders, header => header.Name == ":path" && header.Value == "/delayed-fin");

            byte[] responseHeaders = QPackEncoder.EncodeFieldSection(
            [
                new QPackFieldLine(":status", "200"),
                new QPackFieldLine("content-type", "application/octet-stream"),
                new QPackFieldLine("content-length", (declaredContentLength ?? checked((ulong)responseBody.Length)).ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ]);
            byte[] headersFrame = Http3FrameWriter.WriteHeaders(responseHeaders);
            byte[] dataFrame = Http3FrameWriter.WriteData(responseBody);

            await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
            await requestStream.WriteAsync(dataFrame, 0, dataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
            responsePayloadSent.TrySetResult(null);

            await responseFinAllowed.WaitAsync(TimeSpan.FromSeconds(10));
            await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (Exception exception)
        {
            responsePayloadSent.TrySetException(exception);
            throw;
        }
        finally
        {
            if (requestStream is not null)
            {
                await requestStream.DisposeAsync();
            }

            foreach (QuicStream stream in unidirectionalStreams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    private static async Task ObserveUnidirectionalStreamPreambleAsync(QuicStream stream)
    {
        byte[] buffer = new byte[512];
        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(bytesRead > 0);

        Assert.True(Http3VariableLengthInteger.TryParse(buffer.AsSpan(0, bytesRead), out ulong streamType, out int bytesConsumed));
        Assert.True(
            streamType is (ulong)Http3StreamType.Control
                or (ulong)Http3StreamType.QPackEncoder
                or (ulong)Http3StreamType.QPackDecoder);

        if (streamType != (ulong)Http3StreamType.Control)
        {
            return;
        }

        Http3FrameReader reader = new();
        Http3SettingsFrame? settingsFrame = ReadSettingsFrame(reader.Read(buffer.AsSpan(bytesConsumed, bytesRead - bytesConsumed)));
        while (settingsFrame is null)
        {
            bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(bytesRead > 0);
            settingsFrame = ReadSettingsFrame(reader.Read(buffer.AsSpan(0, bytesRead)));
        }

        Assert.Equal(0UL, settingsFrame.Values.QPackMaxTableCapacity);
        Assert.Equal(0UL, settingsFrame.Values.QPackBlockedStreams);
    }

    private static byte[] EncodeVariableLengthInteger(ulong value)
    {
        Span<byte> destination = stackalloc byte[Http3VariableLengthInteger.MaxEncodedLength];
        Assert.True(Http3VariableLengthInteger.TryFormat(value, destination, out int bytesWritten));
        return destination[..bytesWritten].ToArray();
    }

    private static Http3SettingsFrame? ReadSettingsFrame(IEnumerable<Http3Frame> frames)
    {
        foreach (Http3Frame frame in frames)
        {
            return Assert.IsType<Http3SettingsFrame>(frame);
        }

        return null;
    }

    private static async Task RespondAsync(QuicStream requestStream)
    {
        QPackFieldLine[] requestHeaders = await ReadRequestHeadersAsync(requestStream);
        Assert.Contains(requestHeaders, header => header.Name == ":method" && header.Value == "GET");
        Assert.Contains(requestHeaders, header => header.Name == ":path" && header.Value == "/resource?q=1");
        Assert.Contains(requestHeaders, header => header.Name == ":authority" && header.Value.StartsWith("localhost:", StringComparison.Ordinal));

        byte[] responseHeaders = QPackEncoder.EncodeFieldSection(
        [
            new QPackFieldLine(":status", "200"),
            new QPackFieldLine("content-type", "text/plain"),
        ]);
        byte[] headersFrame = Http3FrameWriter.WriteHeaders(responseHeaders);
        byte[] dataFrame = Http3FrameWriter.WriteData("hello over h3"u8);

        await requestStream.WriteAsync(headersFrame, 0, headersFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.WriteAsync(dataFrame, 0, dataFrame.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task<QPackFieldLine[]> ReadRequestHeadersAsync(QuicStream requestStream)
    {
        Http3FrameReader reader = new();
        byte[] buffer = new byte[1024];
        QPackFieldLine[]? requestHeaders = null;

        while (true)
        {
            int bytesRead = await requestStream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(10));
            if (bytesRead == 0)
            {
                foreach (Http3Frame frame in reader.Complete())
                {
                    requestHeaders = CaptureRequestHeaders(frame, requestHeaders);
                }

                break;
            }

            foreach (Http3Frame frame in reader.Read(buffer.AsSpan(0, bytesRead)))
            {
                requestHeaders = CaptureRequestHeaders(frame, requestHeaders);
            }
        }

        Assert.NotNull(requestHeaders);
        return requestHeaders;
    }

    private static QPackFieldLine[]? CaptureRequestHeaders(Http3Frame frame, QPackFieldLine[]? current)
    {
        if (frame is not Http3HeadersFrame headersFrame)
        {
            return current;
        }

        Assert.Null(current);
        return QPackDecoder.DecodeFieldSection(headersFrame.EncodedFieldSection);
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
}
