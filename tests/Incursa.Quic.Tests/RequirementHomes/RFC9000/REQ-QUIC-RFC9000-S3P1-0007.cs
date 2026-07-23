// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P1-0007")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S3P1_0007
{
    private const int InitialStreamReceiveWindowBytes = 64 * 1024;
    private const int PayloadBytes = 1024 * 1024;

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_AcceptsMaxStreamDataAfterEnteringSendState()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            localBidirectionalSendLimit: 1);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamSendState.Send, sendSnapshot.SendState);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 3), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot updatedSnapshot));
        Assert.Equal(3UL, updatedSnapshot.SendLimit);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 2), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 1,
            length: 2,
            fin: true,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
        Assert.True(dataSentSnapshot.HasFinalSize);
        Assert.Equal(3UL, dataSentSnapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_ResumesOneMiBWriteAsPeerExtendsStreamCredit()
    {
        await using LoopbackConnectionPair pair = await LoopbackConnectionPair.CreateAsync();

        Task<QuicStream> serverAcceptTask = pair.ServerConnection.AcceptInboundStreamAsync().AsTask();
        await Task.Yield();
        Task<QuicStream> clientOpenTask = pair.ClientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask();
        await Task.WhenAll(serverAcceptTask, clientOpenTask).WaitAsync(TimeSpan.FromSeconds(10));

        await using QuicStream serverStream = await serverAcceptTask;
        await using QuicStream clientStream = await clientOpenTask;

        Assert.True(serverStream.Bookkeeping.TryGetStreamSnapshot(
            (ulong)serverStream.Id,
            out QuicConnectionStreamSnapshot initialSnapshot));
        Assert.Equal((ulong)InitialStreamReceiveWindowBytes, initialSnapshot.SendLimit);

        byte[] payload = Enumerable.Range(0, PayloadBytes)
            .Select(static index => (byte)(index % 251))
            .ToArray();

        ValueTask pendingWrite = serverStream.WriteAsync(payload);
        Assert.False(
            pendingWrite.IsCompleted,
            "The 1 MiB write should pause after consuming the peer's initial 64 KiB stream credit.");

        Task<byte[]> receiveTask = ReadExactlyUntilEofAsync(clientStream, PayloadBytes);

        await pendingWrite.AsTask().WaitAsync(TimeSpan.FromSeconds(30));
        await serverStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await serverStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(10));

        byte[] received = await receiveTask.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(payload, received);

        Assert.True(serverStream.Bookkeeping.TryGetStreamSnapshot(
            (ulong)serverStream.Id,
            out QuicConnectionStreamSnapshot completedSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, completedSnapshot.SendState);
        Assert.True(completedSnapshot.HasFinalSize);
        Assert.Equal((ulong)PayloadBytes, completedSnapshot.FinalSize);
    }

    private sealed class LoopbackConnectionPair : IAsyncDisposable
    {
        private LoopbackConnectionPair(
            QuicListener listener,
            QuicConnection serverConnection,
            QuicConnection clientConnection)
        {
            Listener = listener;
            ServerConnection = serverConnection;
            ClientConnection = clientConnection;
        }

        private QuicListener Listener { get; }

        public QuicConnection ServerConnection { get; }

        public QuicConnection ClientConnection { get; }

        public static async Task<LoopbackConnectionPair> CreateAsync()
        {
            using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

            QuicReceiveWindowSizes receiveWindowSizes = new()
            {
                Connection = 2 * PayloadBytes,
                LocallyInitiatedBidirectionalStream = InitialStreamReceiveWindowBytes,
                RemotelyInitiatedBidirectionalStream = InitialStreamReceiveWindowBytes,
                UnidirectionalStream = InitialStreamReceiveWindowBytes,
            };

            QuicServerConnectionOptions serverOptions =
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
            serverOptions.InitialReceiveWindowSizes = receiveWindowSizes;

            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = listenEndPoint,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ListenBacklog = 1,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
            };

            QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
            Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync().AsTask();

            QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
            clientOptions.InitialReceiveWindowSizes = receiveWindowSizes;
            Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

            await Task.WhenAll(acceptConnectionTask, connectTask).WaitAsync(TimeSpan.FromSeconds(10));

            return new LoopbackConnectionPair(
                listener,
                await acceptConnectionTask,
                await connectTask);
        }

        public async ValueTask DisposeAsync()
        {
            await ServerConnection.DisposeAsync();
            await ClientConnection.DisposeAsync();
            await Listener.DisposeAsync();
        }
    }

    private static async Task<byte[]> ReadExactlyUntilEofAsync(QuicStream stream, int expectedLength)
    {
        byte[] buffer = new byte[expectedLength];
        int totalRead = 0;

        while (totalRead < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(totalRead));
            Assert.True(bytesRead > 0, $"Expected {expectedLength} bytes but reached EOF after {totalRead} bytes.");
            totalRead += bytesRead;
        }

        Assert.Equal(0, await stream.ReadAsync(new byte[1]));
        return buffer;
    }
}
