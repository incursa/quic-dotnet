using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0006">The library MUST classify terminal and shutdown outcomes through QuicError and QuicException, including handshake-timeout expiry on the still-pending client-connect path as QuicError.ConnectionTimeout, surface application and transport error codes on the exception where the peer actually provided them, and support per-stream abort direction through QuicAbortDirection, including the combined Both case on the supported bidirectional loopback path, without fabricating broader stream-management parity.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0006")]
public sealed class REQ_QUIC_API_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortWrite_OnTheSupportedLoopbackPath_ProjectsResetAndTerminalErrorsHonestly()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        pair.ClientStream.Abort(QuicAbortDirection.Write, 47);

        QuicException peerReadException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ServerStream.ReadAsync(new byte[1], 0, 1));
        Assert.Equal(QuicError.StreamAborted, peerReadException.QuicError);
        Assert.Equal(47, peerReadException.ApplicationErrorCode);

        QuicException peerReadsClosedException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ServerStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.StreamAborted, peerReadsClosedException.QuicError);
        Assert.Equal(47, peerReadsClosedException.ApplicationErrorCode);

        QuicException localWritesClosedException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.OperationAborted, localWritesClosedException.QuicError);
        Assert.Null(localWritesClosedException.ApplicationErrorCode);

        QuicException localWriteException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.WriteAsync(new byte[] { 0x01 }, 0, 1));
        Assert.Equal(QuicError.OperationAborted, localWriteException.QuicError);
        Assert.Null(localWriteException.ApplicationErrorCode);

        Assert.False(pair.ClientStream.ReadsClosed.IsCompleted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortBoth_OnTheSupportedBidirectionalLoopbackPath_ProjectsResetAndStopSendingHonestly()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        pair.ClientStream.Abort(QuicAbortDirection.Both, 9);

        QuicException clientReadsClosedException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.OperationAborted, clientReadsClosedException.QuicError);
        Assert.Null(clientReadsClosedException.ApplicationErrorCode);

        QuicException clientWritesClosedException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.OperationAborted, clientWritesClosedException.QuicError);
        Assert.Null(clientWritesClosedException.ApplicationErrorCode);

        QuicException serverReadsClosedException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ServerStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.StreamAborted, serverReadsClosedException.QuicError);
        Assert.Equal(9, serverReadsClosedException.ApplicationErrorCode);

        QuicException serverWritesClosedException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ServerStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.StreamAborted, serverWritesClosedException.QuicError);
        Assert.Equal(9, serverWritesClosedException.ApplicationErrorCode);

        QuicException localReadException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.ReadAsync(new byte[1], 0, 1));
        Assert.Equal(QuicError.OperationAborted, localReadException.QuicError);
        Assert.Null(localReadException.ApplicationErrorCode);

        QuicException localWriteException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.WriteAsync(new byte[] { 0xAA }, 0, 1));
        Assert.Equal(QuicError.OperationAborted, localWriteException.QuicError);
        Assert.Null(localWriteException.ApplicationErrorCode);

        QuicException peerReadException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ServerStream.ReadAsync(new byte[1], 0, 1));
        Assert.Equal(QuicError.StreamAborted, peerReadException.QuicError);
        Assert.Equal(9, peerReadException.ApplicationErrorCode);

        QuicException peerWriteException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ServerStream.WriteAsync(new byte[] { 0xAA }, 0, 1));
        Assert.Equal(QuicError.StreamAborted, peerWriteException.QuicError);
        Assert.Equal(9, peerWriteException.ApplicationErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortRead_OnTheSupportedLoopbackPath_ProjectsStopSendingAndTerminalErrorsHonestly()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        pair.ClientStream.Abort(QuicAbortDirection.Read, 53);

        QuicException localReadsClosedException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.OperationAborted, localReadsClosedException.QuicError);
        Assert.Null(localReadsClosedException.ApplicationErrorCode);

        QuicException localReadException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.ReadAsync(new byte[1], 0, 1));
        Assert.Equal(QuicError.OperationAborted, localReadException.QuicError);
        Assert.Null(localReadException.ApplicationErrorCode);

        QuicException peerWritesClosedException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ServerStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.StreamAborted, peerWritesClosedException.QuicError);
        Assert.Equal(53, peerWritesClosedException.ApplicationErrorCode);

        QuicException peerWriteException = await Assert.ThrowsAsync<QuicException>(
            () => pair.ServerStream.WriteAsync(new byte[] { 0x01 }, 0, 1));
        Assert.Equal(QuicError.StreamAborted, peerWriteException.QuicError);
        Assert.Equal(53, peerWriteException.ApplicationErrorCode);

        Assert.False(pair.ClientStream.WritesClosed.IsCompleted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WritesAfterLocalAbort_AreRejectedWithOperationAborted()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        pair.ClientStream.Abort(QuicAbortDirection.Write, 11);

        QuicException exception = await Assert.ThrowsAsync<QuicException>(
            () => pair.ClientStream.WriteAsync(new byte[] { 0x01 }, 0, 1));
        Assert.Equal(QuicError.OperationAborted, exception.QuicError);
        Assert.Null(exception.ApplicationErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectionClose_FaultsPendingReadsClosedAndWritesClosedWithConnectionAborted()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        Task readsClosedTask = pair.ClientStream.ReadsClosed;
        Task writesClosedTask = pair.ClientStream.WritesClosed;

        await pair.ClientConnection.CloseAsync(21);

        QuicException readsClosedException = await Assert.ThrowsAsync<QuicException>(
            () => readsClosedTask.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.ConnectionAborted, readsClosedException.QuicError);
        Assert.Equal(21, readsClosedException.ApplicationErrorCode);

        QuicException writesClosedException = await Assert.ThrowsAsync<QuicException>(
            () => writesClosedTask.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(QuicError.ConnectionAborted, writesClosedException.QuicError);
        Assert.Equal(21, writesClosedException.ApplicationErrorCode);
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
}
