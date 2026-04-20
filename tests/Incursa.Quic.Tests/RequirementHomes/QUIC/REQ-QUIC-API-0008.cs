using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0008">Pending accept, connect, and open-stream operations honor cancellation, still-pending client connect operations also honor HandshakeTimeout, listener or client-host disposal unblocks pending work with terminal outcomes instead of pretending handshake completion, and stream-capacity callbacks do not revive a disposed connection facade.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0008")]
public sealed class REQ_QUIC_API_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task DisposeAsync_SuppressesStreamCapacityCallback()
    {
        int callbackCount = 0;
        TestQuicConnectionOptions options = new()
        {
            StreamCapacityCallback = (_, _) => Interlocked.Increment(ref callbackCount),
        };

        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnection connection = new(runtime, options);

        Action<int, int> observer = GetStreamCapacityObserver(runtime);
        observer(4, 0);

        await connection.DisposeAsync();
        await Task.Delay(200);

        Assert.Equal(0, Volatile.Read(ref callbackCount));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AcceptConnectionAsync_HonorsCancellationWhilePending()
    {
        await using QuicListener listener = await QuicListener.ListenAsync(CreateListenerOptions());
        using CancellationTokenSource cancellationSource = new();

        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync(cancellationSource.Token).AsTask();

        await Task.Yield();
        cancellationSource.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => acceptTask);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DisposeAsync_UnblocksPendingAcceptWithObjectDisposedException()
    {
        QuicListener listener = await QuicListener.ListenAsync(CreateListenerOptions());
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();

        await Task.Yield();
        await listener.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => acceptTask);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectAsync_HonorsCancellationWhilePending()
    {
        using CancellationTokenSource cancellationSource = new();

        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            CreateClientOptions(GetUnusedLoopbackEndPoint()),
            cancellationSource.Token).AsTask();

        await Task.Yield();
        cancellationSource.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connectTask);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectAsync_HonorsHandshakeTimeoutWhilePending()
    {
        using Socket silentPeer = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        silentPeer.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        QuicClientConnectionOptions options = CreateClientOptions((IPEndPoint)silentPeer.LocalEndPoint!);
        options.HandshakeTimeout = TimeSpan.FromMilliseconds(250);

        QuicException exception = await Assert.ThrowsAsync<QuicException>(async () =>
            await QuicConnection.ConnectAsync(options).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Equal(QuicError.ConnectionTimeout, exception.QuicError);
        Assert.Null(exception.ApplicationErrorCode);
        Assert.Null(exception.TransportErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientHostDisposeAsync_UnblocksPendingConnectWithObjectDisposedException()
    {
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            CreateClientOptions(GetUnusedLoopbackEndPoint()),
            "options");
        await using QuicClientConnectionHost host = new(settings);

        Task<QuicConnection> connectTask = host.ConnectAsync().AsTask();

        await Task.Yield();
        await host.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => connectTask);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AcceptInboundStreamAsync_HonorsCancellationWhilePending()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask);

        QuicConnection serverConnection = await acceptConnectionTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            using CancellationTokenSource cancellationSource = new();
            Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync(cancellationSource.Token).AsTask();

            await Task.Yield();
            cancellationSource.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => acceptStreamTask);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OpenOutboundStreamAsync_HonorsCancellationWhilePending()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask);

        QuicConnection serverConnection = await acceptConnectionTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            QuicConnectionRuntime runtime = GetRuntime(clientConnection);
            Func<QuicConnectionEvent, bool> originalDispatcher = GetLocalApiEventDispatcher(runtime);
            TaskCompletionSource<bool> dispatcherEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource<bool> dispatcherRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
            runtime.SetLocalApiEventDispatcher(connectionEvent =>
            {
                dispatcherEntered.TrySetResult(true);
                dispatcherRelease.Task.GetAwaiter().GetResult();
                return originalDispatcher(connectionEvent);
            });

            using CancellationTokenSource cancellationSource = new();
            Task<QuicStream> openStreamTask = Task.Run(
                async () => await clientConnection.OpenOutboundStreamAsync(
                    QuicStreamType.Bidirectional,
                    cancellationSource.Token));

            await dispatcherEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellationSource.Cancel();
            dispatcherRelease.TrySetResult(true);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => openStreamTask);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task OpenOutboundStreamAsync_UnblocksWithObjectDisposedException_WhenConnectionIsDisposedWhilePending()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

        await Task.WhenAll(acceptConnectionTask, connectTask);

        QuicConnection serverConnection = await acceptConnectionTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            QuicConnectionRuntime runtime = GetRuntime(clientConnection);
            Func<QuicConnectionEvent, bool> originalDispatcher = GetLocalApiEventDispatcher(runtime);
            TaskCompletionSource<bool> dispatcherEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource<bool> dispatcherRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);

            runtime.SetLocalApiEventDispatcher(connectionEvent =>
            {
                dispatcherEntered.TrySetResult(true);
                dispatcherRelease.Task.GetAwaiter().GetResult();
                return originalDispatcher(connectionEvent);
            });

            Task<QuicStream> openStreamTask = Task.Run(
                async () => await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional));

            await dispatcherEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Task disposeTask = clientConnection.DisposeAsync().AsTask();
            dispatcherRelease.TrySetResult(true);

            await disposeTask.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await openStreamTask.WaitAsync(TimeSpan.FromSeconds(5)));
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadAsync_HonorsCancellationWhilePendingOnASupportedLoopbackStream()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        byte[] buffer = new byte[16];
        using CancellationTokenSource cancellationSource = new();
        Task<int> readTask = pair.ServerStream.ReadAsync(buffer, 0, buffer.Length, cancellationSource.Token);

        await Task.Yield();
        cancellationSource.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => readTask);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_HonorsCancellationWhilePendingOnASupportedLoopbackStream()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        QuicConnectionRuntime runtime = GetRuntime(pair.ClientConnection);
        Func<QuicConnectionEvent, bool> originalDispatcher = GetLocalApiEventDispatcher(runtime);
        TaskCompletionSource<bool> dispatcherEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> dispatcherRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            if (connectionEvent is QuicConnectionStreamActionEvent { ActionKind: QuicConnectionStreamActionKind.Write })
            {
                dispatcherEntered.TrySetResult(true);
                dispatcherRelease.Task.GetAwaiter().GetResult();
            }

            return originalDispatcher(connectionEvent);
        });

        using CancellationTokenSource cancellationSource = new();
        Task writeTask = Task.Run(
            async () => await pair.ClientStream.WriteAsync(
                new byte[] { 0x01, 0x02, 0x03 },
                0,
                3,
                cancellationSource.Token));

        try
        {
            await dispatcherEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellationSource.Cancel();
            dispatcherRelease.TrySetResult(true);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => writeTask.WaitAsync(TimeSpan.FromSeconds(5)));
        }
        finally
        {
            dispatcherRelease.TrySetResult(true);
        }
    }

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        FieldInfo? runtimeField = typeof(QuicConnection).GetField("runtime", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(runtimeField);
        return Assert.IsType<QuicConnectionRuntime>(runtimeField!.GetValue(connection));
    }

    private static Func<QuicConnectionEvent, bool> GetLocalApiEventDispatcher(QuicConnectionRuntime runtime)
    {
        FieldInfo? dispatcherField = typeof(QuicConnectionRuntime).GetField(
            "localApiEventDispatcher",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(dispatcherField);
        return Assert.IsType<Func<QuicConnectionEvent, bool>>(dispatcherField!.GetValue(runtime));
    }

    private static QuicListenerOptions CreateListenerOptions()
    {
        return new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions()),
        };
    }

    private static QuicClientConnectionOptions CreateClientOptions(IPEndPoint remoteEndPoint)
    {
        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = remoteEndPoint,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                RemoteCertificateValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.RemoteCertificateChainErrors,
            },
        };
    }

    private static IPEndPoint GetUnusedLoopbackEndPoint()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (IPEndPoint)socket.LocalEndPoint!;
    }

    private static Action<int, int> GetStreamCapacityObserver(QuicConnectionRuntime runtime)
    {
        FieldInfo? observerField = typeof(QuicConnectionRuntime).GetField(
            "streamCapacityObserver",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(observerField);
        return Assert.IsType<Action<int, int>>(observerField!.GetValue(runtime));
    }

    private sealed class LoopbackStreamPair : IAsyncDisposable
    {
        private LoopbackStreamPair(
            QuicListener listener,
            QuicConnection serverConnection,
            QuicConnection clientConnection,
            QuicStream serverStream,
            QuicStream clientStream)
        {
            Listener = listener;
            ServerConnection = serverConnection;
            ClientConnection = clientConnection;
            ServerStream = serverStream;
            ClientStream = clientStream;
        }

        public QuicListener Listener { get; }

        public QuicConnection ServerConnection { get; }

        public QuicConnection ClientConnection { get; }

        public QuicStream ServerStream { get; }

        public QuicStream ClientStream { get; }

        public static async Task<LoopbackStreamPair> CreateAsync()
        {
            using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = listenEndPoint,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ListenBacklog = 1,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                    QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
            };

            QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
            Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync().AsTask();
            Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

            await Task.WhenAll(acceptConnectionTask, connectTask);

            QuicConnection serverConnection = await acceptConnectionTask;
            QuicConnection clientConnection = await connectTask;

            Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
            await Task.Yield();
            Task<QuicStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask();
            await Task.WhenAll(acceptStreamTask, openStreamTask);

            return new LoopbackStreamPair(
                listener,
                serverConnection,
                clientConnection,
                await acceptStreamTask,
                await openStreamTask);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await ServerStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ClientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ServerConnection.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ClientConnection.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await Listener.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }
        }
    }

    private sealed class TestQuicConnectionOptions : QuicConnectionOptions
    {
    }
}
