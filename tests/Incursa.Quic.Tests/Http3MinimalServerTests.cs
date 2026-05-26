using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Collection(Http3LoopbackTestCollection.Name)]
public sealed class Http3MinimalServerTests
{
    [Fact]
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
        QuicStream controlStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        byte[] settings = Http3SettingsWriter.WriteInitialControlStream(new Http3Settings());
        await controlStream.WriteAsync(settings, 0, settings.Length).WaitAsync(TimeSpan.FromSeconds(10));

        QuicStream encoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteStreamTypeAsync(encoderStream, Http3StreamType.QPackEncoder);

        QuicStream decoderStream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await WriteStreamTypeAsync(decoderStream, Http3StreamType.QPackDecoder);
    }

    private static async Task WriteGetRequestAsync(QuicStream requestStream, string path)
    {
        await WriteGetRequestHeadersAsync(requestStream, path);
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
            IHttp3DiagnosticsSink? diagnosticsSink = null)
        {
            X509Certificate2 certificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(certificate);
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

        internal async ValueTask<Http3Response> GetAsync(string path, bool completeOnContentLength = false)
        {
            return await Http3Client.GetAsync(
                CreateClientOptions(),
                new Uri($"https://localhost:{Endpoint.Port}{path}"),
                new Http3ClientOptions
                {
                    CompleteResponseOnContentLength = completeOnContentLength,
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
}
