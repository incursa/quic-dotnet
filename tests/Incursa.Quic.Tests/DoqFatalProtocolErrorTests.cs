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

        QuicException exception = await Assert.ThrowsAsync<QuicException>(() =>
            client.QueryAsync(CreateDnsQuery(0x41)).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(QuicError.ConnectionAborted, exception.QuicError);
        Assert.Equal((long)DoqErrorCode.ProtocolError, exception.ApplicationErrorCode);
        Assert.Empty(handler.Queries);
    }

    private static byte[] CreateDnsQuery(byte idLowByte)
        => [0x12, idLowByte, (byte)(0x10 + idLowByte)];

    private static byte[] CreateDnsResponse(ReadOnlySpan<byte> query, byte responseMarker)
        => [0x00, query.Length > 1 ? query[1] : (byte)0x00, responseMarker];

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
