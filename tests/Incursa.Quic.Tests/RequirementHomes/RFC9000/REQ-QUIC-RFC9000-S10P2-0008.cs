using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0008">Open streams MUST be implicitly reset when a CONNECTION_CLOSE frame is sent.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2-0008")]
public sealed class REQ_QUIC_RFC9000_S10P2_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectionClose_EmitsConnectionTerminatedNotificationsForOpenStreams()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        QuicConnectionRuntime clientRuntime = GetRuntime(pair.ClientConnection);
        QuicConnectionRuntime serverRuntime = GetRuntime(pair.ServerConnection);

        TaskCompletionSource<QuicStreamNotification> clientNotification = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<QuicStreamNotification> serverNotification = new(TaskCreationOptions.RunContinuationsAsynchronously);

        _ = clientRuntime.RegisterStreamObserver((ulong)pair.ClientStream.Id, notification => clientNotification.TrySetResult(notification));
        _ = serverRuntime.RegisterStreamObserver((ulong)pair.ServerStream.Id, notification => serverNotification.TrySetResult(notification));

        Assert.False(clientNotification.Task.IsCompleted);
        Assert.False(serverNotification.Task.IsCompleted);
        Assert.True(pair.ClientStream.CanRead);
        Assert.True(pair.ClientStream.CanWrite);
        Assert.True(pair.ServerStream.CanRead);
        Assert.True(pair.ServerStream.CanWrite);

        await pair.ClientConnection.CloseAsync(21);

        QuicStreamNotification clientStreamNotification = await clientNotification.Task.WaitAsync(TimeSpan.FromSeconds(5));
        QuicStreamNotification serverStreamNotification = await serverNotification.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(QuicStreamNotificationKind.ConnectionTerminated, clientStreamNotification.Kind);
        Assert.Equal(QuicStreamNotificationKind.ConnectionTerminated, serverStreamNotification.Kind);

        QuicException clientException = Assert.IsType<QuicException>(clientStreamNotification.Exception);
        QuicException serverException = Assert.IsType<QuicException>(serverStreamNotification.Exception);

        Assert.Equal(QuicError.ConnectionAborted, clientException.QuicError);
        Assert.Equal(21, clientException.ApplicationErrorCode);
        Assert.Equal(QuicError.ConnectionAborted, serverException.QuicError);
        Assert.Equal(21, serverException.ApplicationErrorCode);

        Assert.False(pair.ClientStream.CanRead);
        Assert.False(pair.ClientStream.CanWrite);
        Assert.False(pair.ServerStream.CanRead);
        Assert.False(pair.ServerStream.CanWrite);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task OpenStreamsRemainUnterminatedBeforeConnectionClose()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        QuicConnectionRuntime clientRuntime = GetRuntime(pair.ClientConnection);
        QuicConnectionRuntime serverRuntime = GetRuntime(pair.ServerConnection);

        TaskCompletionSource<QuicStreamNotification> clientNotification = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<QuicStreamNotification> serverNotification = new(TaskCreationOptions.RunContinuationsAsynchronously);

        _ = clientRuntime.RegisterStreamObserver((ulong)pair.ClientStream.Id, notification => clientNotification.TrySetResult(notification));
        _ = serverRuntime.RegisterStreamObserver((ulong)pair.ServerStream.Id, notification => serverNotification.TrySetResult(notification));

        Assert.False(clientNotification.Task.IsCompleted);
        Assert.False(serverNotification.Task.IsCompleted);
        Assert.True(pair.ClientStream.CanRead);
        Assert.True(pair.ClientStream.CanWrite);
        Assert.True(pair.ServerStream.CanRead);
        Assert.True(pair.ServerStream.CanWrite);
        Assert.False(pair.ClientStream.ReadsClosed.IsCompleted);
        Assert.False(pair.ClientStream.WritesClosed.IsCompleted);
        Assert.False(pair.ServerStream.ReadsClosed.IsCompleted);
        Assert.False(pair.ServerStream.WritesClosed.IsCompleted);
    }

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        return connection.Runtime;
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
                QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                    new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

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
}
