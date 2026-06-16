// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0006">An application protocol MAY read data from a stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S2P4_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadAsync_DeliversPeerBytesAndThenEof()
    {
        await using LoopbackConnectionPair pair = await LoopbackConnectionPair.CreateAsync();

        Task<QuicStream> serverAcceptTask = pair.ServerConnection.AcceptInboundStreamAsync().AsTask();
        await Task.Yield();
        Task<QuicStream> clientOpenTask = pair.ClientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask();

        await Task.WhenAll(serverAcceptTask, clientOpenTask);

        await using QuicStream serverStream = await serverAcceptTask;
        await using QuicStream clientStream = await clientOpenTask;

        byte[] payload = [0x11, 0x22, 0x33, 0x44];
        await serverStream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(5));
        await serverStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        byte[] buffer = new byte[payload.Length];
        int bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(buffer));

        Assert.Equal(0, await clientStream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));
        await clientStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact(Skip = "ProtocolLab-sized live-loopback echo is stress coverage; use ProtocolLab package smoke for default release evidence.")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadAsync_DeliversProtocolLabSizedEchoBeforeEof()
    {
        await using LoopbackConnectionPair pair = await LoopbackConnectionPair.CreateAsync();

        byte[] payload = new byte[65_536];
        Random.Shared.NextBytes(payload);

        Task serverTask = Task.Run(async () =>
        {
            await using QuicStream serverStream = await pair.ServerConnection.AcceptInboundStreamAsync()
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            byte[] received = await ReadExactlyUntilEofAsync(serverStream, payload.Length)
                .WaitAsync(TimeSpan.FromSeconds(10));

            Assert.True(payload.AsSpan().SequenceEqual(received));

            await serverStream.WriteAsync(received, 0, received.Length).WaitAsync(TimeSpan.FromSeconds(10));
            await serverStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        });

        await using QuicStream clientStream = await pair.ClientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        await clientStream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await clientStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        byte[] echoed = await ReadExactlyUntilEofAsync(clientStream, payload.Length)
            .WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(payload.AsSpan().SequenceEqual(echoed));
        await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact(Skip = "ProtocolLab-sized live-loopback final echo is stress coverage; use ProtocolLab package smoke for default release evidence.")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadAsync_DeliversProtocolLabSizedFinalEchoBeforeEof()
    {
        await using LoopbackConnectionPair pair = await LoopbackConnectionPair.CreateAsync();

        byte[] payload = new byte[65_536];
        Random.Shared.NextBytes(payload);

        Task serverTask = Task.Run(async () =>
        {
            await using QuicStream serverStream = await pair.ServerConnection.AcceptInboundStreamAsync()
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));

            byte[] received = await ReadExactlyUntilEofAsync(serverStream, payload.Length)
                .WaitAsync(TimeSpan.FromSeconds(10));

            Assert.True(payload.AsSpan().SequenceEqual(received));

            await serverStream.WriteFinalAsync(received, 0, received.Length, CancellationToken.None)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(10));
        });

        await using QuicStream clientStream = await pair.ClientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10));

        await clientStream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(10));
        await clientStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        byte[] echoed = await ReadExactlyUntilEofAsync(clientStream, payload.Length)
            .WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(payload.AsSpan().SequenceEqual(echoed));
        Assert.Equal(0, await clientStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(10)));
        await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Theory(Skip = "ProtocolLab-sized concurrent live-loopback echo is stress coverage; use ProtocolLab package smoke for default release evidence.")]
    [InlineData(16)]
    [InlineData(32)]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadAsync_DeliversConcurrentProtocolLabSizedEchoesBeforeEof(int streamCount)
    {
        await using LoopbackConnectionPair pair = await LoopbackConnectionPair.CreateAsync(streamCount);

        byte[] payload = new byte[65_536];
        Random.Shared.NextBytes(payload);

        Task serverTask = Task.Run(async () =>
        {
            List<Task> streamTasks = new(streamCount);
            for (int i = 0; i < streamCount; i++)
            {
                QuicStream serverStream = await pair.ServerConnection.AcceptInboundStreamAsync()
                    .AsTask()
                    .WaitAsync(TimeSpan.FromSeconds(30));

                streamTasks.Add(Task.Run(async () =>
                {
                    await using (serverStream)
                    {
                        byte[] received = await ReadExactlyUntilEofAsync(serverStream, payload.Length)
                            .WaitAsync(TimeSpan.FromSeconds(30));

                        Assert.True(payload.AsSpan().SequenceEqual(received));

                        await serverStream.WriteAsync(received, 0, received.Length).WaitAsync(TimeSpan.FromSeconds(30));
                        await serverStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(30));
                    }
                }));
            }

            await Task.WhenAll(streamTasks).WaitAsync(TimeSpan.FromSeconds(30));
        });

        using SemaphoreSlim clientConcurrency = new(Math.Min(streamCount, 4));
        Task[] clientTasks = Enumerable.Range(0, streamCount)
            .Select(_ => Task.Run(async () =>
            {
                await clientConcurrency.WaitAsync().WaitAsync(TimeSpan.FromSeconds(30));
                try
                {
                    await using QuicStream clientStream = await pair.ClientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional)
                        .AsTask()
                        .WaitAsync(TimeSpan.FromSeconds(30));

                    await clientStream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(30));
                    await clientStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(30));

                    byte[] echoed = await ReadExactlyUntilEofAsync(clientStream, payload.Length)
                        .WaitAsync(TimeSpan.FromSeconds(30));

                    Assert.True(payload.AsSpan().SequenceEqual(echoed));
                }
                finally
                {
                    clientConcurrency.Release();
                }
            }))
            .ToArray();

        await Task.WhenAll(clientTasks).WaitAsync(TimeSpan.FromSeconds(30));
        await serverTask.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ReadAsync_RejectsAStreamWithoutReadableSides()
    {
        await using LoopbackConnectionPair pair = await LoopbackConnectionPair.CreateAsync();
        await using QuicStream stream = await pair.ClientConnection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional);

        // QuicStream derives from Stream, and CA2022 still flags this exact read-path assertion.
#pragma warning disable CA2022
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await stream.ReadAsync(new byte[1].AsMemory()));
#pragma warning restore CA2022
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

        public QuicListener Listener { get; }

        public QuicConnection ServerConnection { get; }

        public QuicConnection ClientConnection { get; }

        public static async Task<LoopbackConnectionPair> CreateAsync(int expectedConcurrentBidirectionalStreams = 0)
        {
            using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

            QuicReceiveWindowSizes receiveWindowSizes = new()
            {
                Connection = 16 * 1024 * 1024,
                LocallyInitiatedBidirectionalStream = 16 * 1024 * 1024,
                RemotelyInitiatedBidirectionalStream = 16 * 1024 * 1024,
                UnidirectionalStream = 16 * 1024 * 1024,
            };

            QuicServerConnectionOptions serverOptions =
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
            serverOptions.InitialReceiveWindowSizes = receiveWindowSizes;
            if (expectedConcurrentBidirectionalStreams > 0)
            {
                serverOptions.MaxInboundBidirectionalStreams = Math.Max(
                    serverOptions.MaxInboundBidirectionalStreams,
                    expectedConcurrentBidirectionalStreams + 8);
            }

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
            if (expectedConcurrentBidirectionalStreams > 0)
            {
                clientOptions.MaxInboundBidirectionalStreams = Math.Max(
                    clientOptions.MaxInboundBidirectionalStreams,
                    expectedConcurrentBidirectionalStreams + 8);
            }
            Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
                clientOptions).AsTask();

            await Task.WhenAll(acceptConnectionTask, connectTask);

            QuicConnection serverConnection = await acceptConnectionTask;
            QuicConnection clientConnection = await connectTask;
            return new LoopbackConnectionPair(listener, serverConnection, clientConnection);
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
            int bytesRead = await stream.ReadAsync(buffer, totalRead, buffer.Length - totalRead);
            if (bytesRead == 0)
            {
                break;
            }

            totalRead += bytesRead;
        }

        Assert.Equal(expectedLength, totalRead);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], 0, 1));
        return buffer;
    }
}
