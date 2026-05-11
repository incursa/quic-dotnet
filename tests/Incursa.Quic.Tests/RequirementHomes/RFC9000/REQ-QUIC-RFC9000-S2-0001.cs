using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0001">Streams in QUIC MUST provide applications with an ordered byte-stream abstraction.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2-0001")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LoopbackStream_PreservesApplicationWriteOrderAcrossChunkedWrites()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        byte[] firstChunk = [0x11, 0x22];
        byte[] secondChunk = [0x33, 0x44, 0x55];

        await pair.ClientStream.WriteAsync(firstChunk, 0, firstChunk.Length).WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.WriteAsync(secondChunk, 0, secondChunk.Length).WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        byte[] expected = [0x11, 0x22, 0x33, 0x44, 0x55];
        byte[] receiveBuffer = new byte[expected.Length];
        int bytesRead = await pair.ServerStream.ReadAsync(
            receiveBuffer,
            0,
            receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(expected.Length, bytesRead);
        Assert.True(expected.AsSpan().SequenceEqual(receiveBuffer));

        Assert.Equal(0, await pair.ServerStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ServerStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
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
