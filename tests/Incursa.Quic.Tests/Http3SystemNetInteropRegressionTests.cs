// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Incursa.Qpack;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Tests;

[Collection(Http3LoopbackTestCollection.Name)]
public sealed class Http3SystemNetInteropRegressionTests
{
    [Fact]
    public void ReturnedServerOptionsReplacePreHandshakeIncomingStreamLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            incomingBidirectionalStreamLimit: 100,
            incomingUnidirectionalStreamLimit: 3);

        Assert.True(state.TryApplyInitialIncomingStreamLimits(512, 16));
        Assert.Equal(512UL, state.IncomingBidirectionalStreamLimit);
        Assert.Equal(16UL, state.IncomingUnidirectionalStreamLimit);
        Assert.False(state.TryApplyInitialIncomingStreamLimits(512, 16));
    }

    [Fact]
    public void InitialIncomingStreamLimitsCannotChangeAfterPeerStreamCreation()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: true,
            incomingBidirectionalStreamLimit: 100);
        Assert.True(state.TryReceiveStreamFrame(
            new QuicStreamFrame(
                frameType: 0x0a,
                streamId: new QuicStreamId(0),
                hasOffset: false,
                offset: 0,
                hasLength: true,
                length: 1,
                fin: false,
                streamData: [0x01],
                consumedLength: 3),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.Throws<InvalidOperationException>(() => state.TryApplyInitialIncomingStreamLimits(512, 16));
    }

    [Fact]
    [Trait("Category", "Regression")]
    public async Task SystemNetClient_RepeatedlyPostsAndEchoesExact64KiBBody()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(64 * 1024);
        await using SystemNetInteropServer server = await SystemNetInteropServer.StartAsync(new EchoHandler());

        for (int requestIndex = 0; requestIndex < 1024; requestIndex++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, server.CreateUri("/echo"))
            {
                Version = HttpVersion.Version30,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new ByteArrayContent(body)
            };
            using HttpResponseMessage response = await SendWithRequestIndexAsync(server, request, requestIndex);
            byte[] echoed = await response.Content.ReadAsByteArrayAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(HttpVersion.Version30, response.Version);
            Assert.Equal(body, echoed);
        }
    }

    [Fact]
    [Trait("Category", "Regression")]
    public async Task SystemNetClient_PostsExactOneMiBBody()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(1024 * 1024);
        await using SystemNetInteropServer server = await SystemNetInteropServer.StartAsync(new EchoHandler());
        using var request = new HttpRequestMessage(HttpMethod.Post, server.CreateUri("/echo"))
        {
            Version = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = new ByteArrayContent(body)
        };
        using HttpResponseMessage response = await server.SendAsync(request);
        byte[] echoed = await response.Content.ReadAsByteArrayAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpVersion.Version30, response.Version);
        Assert.Equal(body, echoed);
    }

    [Fact]
    [Trait("Category", "Regression")]
    public async Task SystemNetClient_RepeatedOneMiBResponsesCompleteExactly()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        byte[] body = CreateDeterministicBytes(1024 * 1024);
        await using SystemNetInteropServer server = await SystemNetInteropServer.StartAsync(
            new FixedBodyHandler(body));

        for (int requestIndex = 0; requestIndex < 32; requestIndex++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, server.CreateUri($"/large?request={requestIndex}"))
            {
                Version = HttpVersion.Version30,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact
            };
            using HttpResponseMessage response = await server.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            byte[] received = await response.Content.ReadAsByteArrayAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(HttpVersion.Version30, response.Version);
            Assert.Equal(body, received);
        }
    }

    private static byte[] CreateDeterministicBytes(int length)
    {
        byte[] payload = GC.AllocateUninitializedArray<byte>(length);
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = unchecked((byte)index);
        }

        return payload;
    }

    private static async Task<HttpResponseMessage> SendWithRequestIndexAsync(
        SystemNetInteropServer server,
        HttpRequestMessage request,
        int requestIndex)
    {
        try
        {
            return await server.SendAsync(request);
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException($"Native HTTP/3 request {requestIndex} failed.", exception);
        }
    }

    private sealed class EchoHandler : IHttp3RequestHandler
    {
        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(CreateResponse(request.Body));
    }

    private sealed class FixedBodyHandler(ReadOnlyMemory<byte> body) : IHttp3RequestHandler
    {
        private readonly Http3ServerResponse response = CreateResponse(body);

        public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(response);
    }

    private static Http3ServerResponse CreateResponse(ReadOnlyMemory<byte> body)
    {
        QPackFieldLine[] headers =
        [
            new("content-type", "application/octet-stream"),
            new("content-length", body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("server", "Incursa.Quic.Http3")
        ];
        return Http3ServerResponse.CreateFromImmutableBodyAndHeaders(200, body, headers);
    }

    private sealed class SystemNetInteropServer : IAsyncDisposable
    {
        private readonly X509Certificate2 certificate;
        private readonly Http3Server server;
        private readonly CancellationTokenSource shutdown;
        private readonly Task serverTask;
        private readonly LifecycleOnlyDiagnosticsSink diagnostics;

        private SystemNetInteropServer(
            X509Certificate2 certificate,
            Http3Server server,
            CancellationTokenSource shutdown,
            Task serverTask,
            IPEndPoint endPoint,
            HttpClient client,
            LifecycleOnlyDiagnosticsSink diagnostics)
        {
            this.certificate = certificate;
            this.server = server;
            this.shutdown = shutdown;
            this.serverTask = serverTask;
            this.diagnostics = diagnostics;
            EndPoint = endPoint;
            Client = client;
        }

        public IPEndPoint EndPoint { get; }

        public HttpClient Client { get; }

        public static async Task<SystemNetInteropServer> StartAsync(IHttp3RequestHandler handler)
        {
            X509Certificate2 certificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
            IPEndPoint endPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            QuicServerConnectionOptions serverOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(certificate);
            serverOptions.MaxInboundBidirectionalStreams = 512;
            serverOptions.MaxInboundUnidirectionalStreams = 16;
            serverOptions.InitialReceiveWindowSizes = new QuicReceiveWindowSizes
            {
                Connection = 16 * 1024 * 1024,
                LocallyInitiatedBidirectionalStream = 16 * 1024 * 1024,
                RemotelyInitiatedBidirectionalStream = 16 * 1024 * 1024,
                UnidirectionalStream = 16 * 1024 * 1024
            };
            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = endPoint,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ListenBacklog = 16,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions)
            };
            var diagnostics = new LifecycleOnlyDiagnosticsSink();
            Http3Server server = await Http3Server.ListenAsync(
                listenerOptions,
                handler,
                new Http3ServerOptions { DiagnosticsSink = diagnostics });
            CancellationTokenSource shutdown = new(TimeSpan.FromMinutes(2));
            Task serverTask = server.ServeAsync(shutdown.Token);
            var socketsHandler = new SocketsHttpHandler
            {
                EnableMultipleHttp3Connections = true,
                SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = static (_, _, _, _) => true
                }
            };
            var client = new HttpClient(socketsHandler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            return new SystemNetInteropServer(certificate, server, shutdown, serverTask, endPoint, client, diagnostics);
        }

        public Uri CreateUri(string path) => new($"https://127.0.0.1:{EndPoint.Port}{path}");

        public async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead)
        {
            try
            {
                return await Client.SendAsync(request, completionOption);
            }
            catch (Exception exception)
            {
                string details = string.Join(
                    " | ",
                    diagnostics.Events
                        .GroupBy(static item => item.Kind)
                        .OrderBy(static group => group.Key)
                        .Select(static group => $"{group.Key}={group.Count()}"));
                throw new InvalidOperationException($"Native HTTP/3 request failed. Server diagnostics: {details}", exception);
            }
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            shutdown.Cancel();
            await server.DisposeAsync();
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
            shutdown.Dispose();
            certificate.Dispose();
        }
    }

    private sealed class LifecycleOnlyDiagnosticsSink : IHttp3DiagnosticKindFilter
    {
        private readonly object gate = new();
        private readonly List<Http3DiagnosticEvent> events = [];

        public bool IsEnabled => true;

        public IReadOnlyList<Http3DiagnosticEvent> Events
        {
            get
            {
                lock (gate)
                {
                    return [.. events];
                }
            }
        }

        public bool IsEnabledFor(Http3DiagnosticKind kind)
            => kind is Http3DiagnosticKind.ConnectionStarted
                or Http3DiagnosticKind.ConnectionClosed
                or Http3DiagnosticKind.RequestStarted
                or Http3DiagnosticKind.RequestCompleted;

        public void Emit(Http3DiagnosticEvent diagnosticEvent)
        {
            lock (gate)
            {
                events.Add(diagnosticEvent);
            }
        }
    }
}
