// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0007">A CONNECTION_CLOSE frame MUST cause all streams to immediately become closed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2-0007")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S10P2_0007
{
    private static readonly TimeSpan ClosePropagationTimeout = TimeSpan.FromSeconds(15);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ConnectionClose_ClosesBothEndsOfAnOpenStream()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        Task clientReadsClosedTask = pair.ClientStream.ReadsClosed;
        Task clientWritesClosedTask = pair.ClientStream.WritesClosed;
        Task serverReadsClosedTask = pair.ServerStream.ReadsClosed;
        Task serverWritesClosedTask = pair.ServerStream.WritesClosed;

        await pair.ClientConnection.CloseAsync(21);

        await AssertConnectionAbortedAsync(clientReadsClosedTask, 21);
        await AssertConnectionAbortedAsync(clientWritesClosedTask, 21);
        await AssertConnectionAbortedAsync(serverReadsClosedTask, 21);
        await AssertConnectionAbortedAsync(serverWritesClosedTask, 21);

        Assert.False(pair.ClientStream.CanRead);
        Assert.False(pair.ClientStream.CanWrite);
        Assert.False(pair.ServerStream.CanRead);
        Assert.False(pair.ServerStream.CanWrite);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task OpenStreamSidesRemainPendingBeforeConnectionClose()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        Assert.False(pair.ClientStream.ReadsClosed.IsCompleted);
        Assert.False(pair.ClientStream.WritesClosed.IsCompleted);
        Assert.False(pair.ServerStream.ReadsClosed.IsCompleted);
        Assert.False(pair.ServerStream.WritesClosed.IsCompleted);
        Assert.True(pair.ClientStream.CanRead);
        Assert.True(pair.ClientStream.CanWrite);
        Assert.True(pair.ServerStream.CanRead);
        Assert.True(pair.ServerStream.CanWrite);
    }

    private static async Task AssertConnectionAbortedAsync(Task closedTask, long expectedApplicationErrorCode)
    {
        QuicException exception = await Assert.ThrowsAsync<QuicException>(
            () => closedTask.WaitAsync(ClosePropagationTimeout));
        Assert.Equal(QuicError.ConnectionAborted, exception.QuicError);
        Assert.Equal(expectedApplicationErrorCode, exception.ApplicationErrorCode);
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
