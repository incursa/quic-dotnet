// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

public sealed class QuicListenerHostSendResilienceTests
{
    [Fact]
    public void TransientUdpSendFailureDoesNotEscapeAndLaterSendStillRuns()
    {
        int sendAttempts = 0;
        using QuicListenerHost listenerHost = CreateHost((payload, _) =>
        {
            if (Interlocked.Increment(ref sendAttempts) == 1)
            {
                throw new SocketException((int)SocketError.NoBufferSpaceAvailable);
            }

            return payload.Length;
        });

        QuicConnectionSendDatagramEffect effect = CreateDatagramEffect(listenerHost);

        listenerHost.SendDatagram(effect);
        listenerHost.SendDatagram(effect);

        Assert.Equal(2, sendAttempts);
    }

    [Fact]
    public void IncompleteUdpSendDoesNotEscapeAndLaterSendStillRuns()
    {
        int sendAttempts = 0;
        using QuicListenerHost listenerHost = CreateHost((payload, _) =>
        {
            int attempt = Interlocked.Increment(ref sendAttempts);
            return attempt == 1 ? payload.Length - 1 : payload.Length;
        });

        QuicConnectionSendDatagramEffect effect = CreateDatagramEffect(listenerHost);

        listenerHost.SendDatagram(effect);
        listenerHost.SendDatagram(effect);

        Assert.Equal(2, sendAttempts);
    }

    [Theory]
    [InlineData(SocketError.Interrupted)]
    [InlineData(SocketError.WouldBlock)]
    [InlineData(SocketError.TryAgain)]
    [InlineData(SocketError.NoBufferSpaceAvailable)]
    public void TransientSendSocketErrorsAreRecoverable(SocketError socketError)
    {
        Assert.True(QuicListenerHost.IsTransientSendSocketError(socketError));
    }

    [Theory]
    [InlineData(SocketError.InvalidArgument)]
    [InlineData(SocketError.AddressFamilyNotSupported)]
    [InlineData(SocketError.NetworkDown)]
    public void PermanentSendSocketErrorsAreNotHidden(SocketError socketError)
    {
        Assert.False(QuicListenerHost.IsTransientSendSocketError(socketError));

        using QuicListenerHost listenerHost = CreateHost((_, _) => throw new SocketException((int)socketError));
        Assert.Throws<SocketException>(() => listenerHost.SendDatagram(CreateDatagramEffect(listenerHost)));
    }

    [Theory]
    [InlineData(SocketError.ConnectionReset)]
    [InlineData(SocketError.ConnectionAborted)]
    [InlineData(SocketError.ConnectionRefused)]
    [InlineData(SocketError.HostUnreachable)]
    [InlineData(SocketError.NetworkUnreachable)]
    [InlineData(SocketError.NetworkReset)]
    [InlineData(SocketError.TimedOut)]
    public void PeerPathSendSocketErrorsDoNotInvalidateTheSharedListener(SocketError socketError)
    {
        Assert.True(QuicListenerHost.IsPeerPathSendSocketError(socketError));
    }

    [Fact]
    public async Task DroppedServerFinIsRecoveredAndShardContinuesProcessing()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        QuicListenerHost? listenerHost = null;
        QuicConnection? serverConnection = null;
        int dropNextSend = 0;
        int droppedSends = 0;
        int droppedFin = 0;
        int retransmittedFin = 0;
        long droppedFinPacketNumber = -1;

        listenerHost = new QuicListenerHost(
            new IPEndPoint(IPAddress.Loopback, 0),
            [SslApplicationProtocol.Http3],
            (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
            listenBacklog: 1,
            runtimeShardCount: 4,
            datagramSender: (payload, destination) =>
            {
                bool carriesFin = serverConnection is not null && LatestApplicationPacketCarriesFin(serverConnection.Runtime);
                if (carriesFin
                    && Volatile.Read(ref dropNextSend) != 0
                    && Interlocked.Exchange(ref dropNextSend, 0) != 0)
                {
                    Interlocked.Increment(ref droppedSends);
                    Interlocked.Exchange(
                        ref droppedFinPacketNumber,
                        checked((long)GetLatestApplicationPacketNumber(serverConnection.Runtime)));
                    Volatile.Write(ref droppedFin, 1);

                    throw new SocketException((int)SocketError.NoBufferSpaceAvailable);
                }

                if (Volatile.Read(ref droppedFin) != 0
                    && ApplicationPacketWithFinWasSentAfter(
                        serverConnection!.Runtime,
                        checked((ulong)Volatile.Read(ref droppedFinPacketNumber))))
                {
                    Volatile.Write(ref retransmittedFin, 1);
                }

                return listenerHost!.Socket.SendTo(payload.Span, SocketFlags.None, destination);
            });

        Task listenerTask = listenerHost.RunAsync();
        IPEndPoint listenerEndPoint = (IPEndPoint)listenerHost.Socket.LocalEndPoint!;
        Task<QuicConnection> acceptTask = listenerHost.AcceptConnectionAsync().AsTask();
        await using QuicConnection clientConnection = await QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(listenerEndPoint));
        serverConnection = await acceptTask;
        await using QuicConnection ownedServerConnection = serverConnection;

        await AssertFinRecoveryAsync(clientConnection, ownedServerConnection, () => Volatile.Write(ref dropNextSend, 1));
        await AssertSimpleRoundTripAsync(clientConnection, ownedServerConnection);

        Assert.Equal(1, droppedSends);
        Assert.Equal(1, droppedFin);
        Assert.Equal(1, retransmittedFin);
        Assert.False(listenerTask.IsFaulted);

        await listenerHost.DisposeAsync();
        await listenerTask;
    }

    [Fact]
    public async Task SilentlyDroppedServerFinIsRecoveredAcrossHighFanoutAndConnectionRemainsUsable()
    {
        const int streamCount = 100;
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        QuicListenerHost? listenerHost = null;
        QuicConnection? serverConnection = null;
        int dropNextSend = 0;
        int droppedFin = 0;

        listenerHost = new QuicListenerHost(
            new IPEndPoint(IPAddress.Loopback, 0),
            [SslApplicationProtocol.Http3],
            (_, _, _) =>
            {
                QuicServerConnectionOptions options =
                    QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
                options.MaxInboundBidirectionalStreams = streamCount + 8;
                return ValueTask.FromResult(options);
            },
            listenBacklog: 1,
            runtimeShardCount: 4,
            datagramSender: (payload, destination) =>
            {
                if (Volatile.Read(ref dropNextSend) != 0
                    && Interlocked.Exchange(ref dropNextSend, 0) != 0)
                {
                    Interlocked.Increment(ref droppedFin);
                    return payload.Length;
                }

                return listenerHost!.Socket.SendTo(payload.Span, SocketFlags.None, destination);
            });

        Task listenerTask = listenerHost.RunAsync();
        IPEndPoint listenerEndPoint = (IPEndPoint)listenerHost.Socket.LocalEndPoint!;
        Task<QuicConnection> acceptTask = listenerHost.AcceptConnectionAsync().AsTask();
        await using QuicConnection clientConnection = await QuicConnection.ConnectAsync(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(listenerEndPoint));
        serverConnection = await acceptTask;
        await using QuicConnection ownedServerConnection = serverConnection;

        List<QuicStream> clientStreams = new(streamCount);
        List<QuicStream> serverStreams = new(streamCount);
        try
        {
            for (int index = 0; index < streamCount; index++)
            {
                Task<QuicStream> acceptStreamTask = ownedServerConnection.AcceptInboundStreamAsync().AsTask();
                QuicStream clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
                QuicStream serverStream = await acceptStreamTask;
                clientStreams.Add(clientStream);
                serverStreams.Add(serverStream);

                await clientStream.WriteAsync(new byte[] { (byte)index });
                await clientStream.CompleteWritesAsync();
            }

            await Task.WhenAll(serverStreams.Select(ReadRequestToEofAsync));

            byte[] response = new byte[1024];
            await Task.WhenAll(serverStreams.Select(stream => stream.WriteAsync(response).AsTask()));

            // Prove every payload byte arrived before completing writes so the test specifically
            // loses a FIN-only tail packet, matching the ProtocolLab failure.
            await Task.WhenAll(clientStreams.Select(stream => ReadExactResponseAsync(stream, response.Length)));
            Volatile.Write(ref dropNextSend, 1);
            await serverStreams[0].CompleteWritesAsync();
            await WaitForConditionAsync(() => Volatile.Read(ref droppedFin) == 1, TimeSpan.FromSeconds(5));
            await serverStreams[0].DisposeAsync();
            await Task.WhenAll(serverStreams.Skip(1).Select(stream => stream.CompleteWritesAsync().AsTask()));

            await Task.WhenAll(clientStreams.Select(ReadEofAsync));
            await AssertSimpleRoundTripAsync(clientConnection, ownedServerConnection);

            Assert.Equal(1, droppedFin);
            Assert.False(listenerTask.IsFaulted);
        }
        finally
        {
            foreach (QuicStream stream in clientStreams)
            {
                await stream.DisposeAsync();
            }

            foreach (QuicStream stream in serverStreams)
            {
                await stream.DisposeAsync();
            }
        }

        await listenerHost.DisposeAsync();
        await listenerTask;
    }

    [Fact]
    public async Task ConcurrentConnectionsCompleteEveryHighFanoutStream()
    {
        const int connectionCount = 16;
        const int streamCount = 100;
        const int responseLength = 1024;
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        using QuicListenerHost listenerHost = new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [SslApplicationProtocol.Http3],
            (_, _, _) =>
            {
                QuicServerConnectionOptions options =
                    QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
                options.MaxInboundBidirectionalStreams = streamCount + 8;
                return ValueTask.FromResult(options);
            },
            listenBacklog: connectionCount,
            runtimeShardCount: 4);

        Task listenerTask = listenerHost.RunAsync();
        IPEndPoint listenerEndPoint = (IPEndPoint)listenerHost.Socket.LocalEndPoint!;
        Task<QuicConnection>[] acceptTasks = Enumerable.Range(0, connectionCount)
            .Select(_ => listenerHost.AcceptConnectionAsync().AsTask())
            .ToArray();
        Task<QuicConnection>[] connectTasks = Enumerable.Range(0, connectionCount)
            .Select(_ => QuicConnection.ConnectAsync(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(listenerEndPoint)).AsTask())
            .ToArray();

        QuicConnection[] clientConnections = await Task.WhenAll(connectTasks).WaitAsync(TimeSpan.FromSeconds(20));
        QuicConnection[] serverConnections = await Task.WhenAll(acceptTasks).WaitAsync(TimeSpan.FromSeconds(20));
        int[] serverReadEofCounts = new int[connectionCount];
        int[] serverPayloadWriteCounts = new int[connectionCount];
        int[] serverCompletedWriteCounts = new int[connectionCount];
        int[] clientPayloadCounts = new int[connectionCount];
        int[] clientReadEofCounts = new int[connectionCount];

        try
        {
            Task[] serverTasks = serverConnections
                .Select((connection, index) => ServeHighFanoutConnectionAsync(
                    connection,
                    index,
                    streamCount,
                    responseLength,
                    serverReadEofCounts,
                    serverPayloadWriteCounts,
                    serverCompletedWriteCounts))
                .ToArray();
            Task[] clientTasks = clientConnections
                .Select((connection, index) => RunHighFanoutClientAsync(
                    connection,
                    index,
                    streamCount,
                    responseLength,
                    clientPayloadCounts,
                    clientReadEofCounts))
                .ToArray();

            try
            {
                await Task.WhenAll(clientTasks.Concat(serverTasks)).WaitAsync(TimeSpan.FromSeconds(30));
            }
            catch (TimeoutException ex)
            {
                throw new TimeoutException(
                    $"High-fanout progress timed out. " +
                    $"serverReadEof=[{string.Join(',', serverReadEofCounts)}], " +
                    $"serverPayloadWrites=[{string.Join(',', serverPayloadWriteCounts)}], " +
                    $"serverCompletedWrites=[{string.Join(',', serverCompletedWriteCounts)}], " +
                    $"clientPayload=[{string.Join(',', clientPayloadCounts)}], " +
                    $"clientReadEof=[{string.Join(',', clientReadEofCounts)}]",
                    ex);
            }

            Assert.False(listenerTask.IsFaulted);
        }
        finally
        {
            foreach (QuicConnection connection in clientConnections)
            {
                await connection.DisposeAsync();
            }

            foreach (QuicConnection connection in serverConnections)
            {
                await connection.DisposeAsync();
            }
        }

        await listenerHost.DisposeAsync();
        await listenerTask;
    }

    [Fact]
    public async Task ConcurrentColdHandshakesRemainAcceptableWithTwoRuntimeShards()
    {
        const int connectionCount = 128;
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        using QuicListenerHost listenerHost = new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [SslApplicationProtocol.Http3],
            (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
            listenBacklog: connectionCount,
            runtimeShardCount: 2);

        Task listenerTask = listenerHost.RunAsync();
        IPEndPoint listenerEndPoint = (IPEndPoint)listenerHost.Socket.LocalEndPoint!;
        Task<QuicConnection>[] acceptTasks = Enumerable.Range(0, connectionCount)
            .Select(_ => listenerHost.AcceptConnectionAsync().AsTask())
            .ToArray();
        Task<QuicConnection>[] connectTasks = Enumerable.Range(0, connectionCount)
            .Select(_ => QuicConnection.ConnectAsync(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(listenerEndPoint)).AsTask())
            .ToArray();

        QuicConnection[] clientConnections = [];
        QuicConnection[] serverConnections = [];
        try
        {
            clientConnections = await Task.WhenAll(connectTasks).WaitAsync(TimeSpan.FromSeconds(30));
            serverConnections = await Task.WhenAll(acceptTasks).WaitAsync(TimeSpan.FromSeconds(30));

            Assert.Equal(connectionCount, clientConnections.Length);
            Assert.Equal(connectionCount, serverConnections.Length);
            Assert.False(listenerTask.IsFaulted);
        }
        finally
        {
            foreach (QuicConnection connection in clientConnections)
            {
                await connection.DisposeAsync();
            }

            foreach (QuicConnection connection in serverConnections)
            {
                await connection.DisposeAsync();
            }

            await listenerHost.DisposeAsync();
            await listenerTask;
        }
    }

    private static QuicListenerHost CreateHost(Func<ReadOnlyMemory<byte>, SocketAddress, int> datagramSender)
        => new(
            new IPEndPoint(IPAddress.Loopback, 0),
            [SslApplicationProtocol.Http3],
            static (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions()),
            listenBacklog: 1,
            datagramSender: datagramSender);

    private static QuicConnectionSendDatagramEffect CreateDatagramEffect(QuicListenerHost listenerHost)
    {
        IPEndPoint localEndPoint = (IPEndPoint)listenerHost.Socket.LocalEndPoint!;
        QuicConnectionPathIdentity path = new(
            RemoteAddress: IPAddress.Loopback.ToString(),
            LocalAddress: localEndPoint.Address.ToString(),
            RemotePort: 44321,
            LocalPort: localEndPoint.Port);

        return new QuicConnectionSendDatagramEffect(path, new byte[1200]);
    }

    private static async Task AssertFinRecoveryAsync(
        QuicConnection clientConnection,
        QuicConnection serverConnection,
        Action dropNextSend)
    {
        Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
        await using QuicStream clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        await using QuicStream serverStream = await acceptStreamTask;

        await clientStream.WriteAsync(new byte[] { 0x2A });
        await clientStream.CompleteWritesAsync();
        byte[] request = new byte[1];
        Assert.Equal(1, await serverStream.ReadAsync(request).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(0, await serverStream.ReadAsync(request).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        byte[] response = new byte[64 * 1024];
        await serverStream.WriteAsync(response);
        dropNextSend();
        await serverStream.CompleteWritesAsync();

        int received = 0;
        while (received < response.Length)
        {
            int read = await clientStream.ReadAsync(response.AsMemory(received)).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(read > 0);
            received += read;
        }

        Assert.Equal(0, await clientStream.ReadAsync(new byte[1]).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
    }

    private static async Task AssertSimpleRoundTripAsync(
        QuicConnection clientConnection,
        QuicConnection serverConnection)
    {
        Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
        await using QuicStream clientStream = await clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        await using QuicStream serverStream = await acceptStreamTask;

        await clientStream.WriteAsync(new byte[] { 0x7B });
        await clientStream.CompleteWritesAsync();
        byte[] request = new byte[1];
        Assert.Equal(1, await serverStream.ReadAsync(request).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(0, await serverStream.ReadAsync(request).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        await serverStream.WriteAsync(request);
        await serverStream.CompleteWritesAsync();
        Assert.Equal(1, await clientStream.ReadAsync(request).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(0, await clientStream.ReadAsync(request).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
    }

    private static async Task ReadRequestToEofAsync(QuicStream stream)
    {
        byte[] request = new byte[1];
        Assert.Equal(1, await stream.ReadAsync(request).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(0, await stream.ReadAsync(request).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
    }

    private static async Task ReadExactResponseAsync(QuicStream stream, int expectedLength)
    {
        byte[] response = new byte[expectedLength];
        int received = 0;
        while (received < response.Length)
        {
            int read = await stream.ReadAsync(response.AsMemory(received)).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(read > 0);
            received += read;
        }
    }

    private static async Task ReadEofAsync(QuicStream stream)
    {
        Assert.Equal(0, await stream.ReadAsync(new byte[1]).AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
    }

    private static async Task ServeHighFanoutConnectionAsync(
        QuicConnection connection,
        int connectionIndex,
        int streamCount,
        int responseLength,
        int[] readEofCounts,
        int[] payloadWriteCounts,
        int[] completedWriteCounts)
    {
        List<QuicStream> streams = new(streamCount);
        try
        {
            for (int index = 0; index < streamCount; index++)
            {
                streams.Add(await connection.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)));
            }

            byte[] response = new byte[responseLength];
            await Task.WhenAll(streams.Select(async stream =>
            {
                await ReadRequestToEofAsync(stream);
                Interlocked.Increment(ref readEofCounts[connectionIndex]);
                await stream.WriteAsync(response);
                Interlocked.Increment(ref payloadWriteCounts[connectionIndex]);
                await stream.CompleteWritesAsync();
                Interlocked.Increment(ref completedWriteCounts[connectionIndex]);
            }));
        }
        finally
        {
            foreach (QuicStream stream in streams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    private static async Task RunHighFanoutClientAsync(
        QuicConnection connection,
        int connectionIndex,
        int streamCount,
        int responseLength,
        int[] payloadCounts,
        int[] readEofCounts)
    {
        List<QuicStream> streams = new(streamCount);
        try
        {
            for (int index = 0; index < streamCount; index++)
            {
                QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
                streams.Add(stream);
                await stream.WriteAsync(new byte[] { (byte)index });
                await stream.CompleteWritesAsync();
            }

            await Task.WhenAll(streams.Select(async stream =>
            {
                await ReadExactResponseAsync(stream, responseLength);
                Interlocked.Increment(ref payloadCounts[connectionIndex]);
                await ReadEofAsync(stream);
                Interlocked.Increment(ref readEofCounts[connectionIndex]);
            }));
        }
        finally
        {
            foreach (QuicStream stream in streams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    private static async Task WaitForConditionAsync(Func<bool> condition, TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "The expected datagram was not observed before the timeout.");
            await Task.Delay(10);
        }
    }

    private static bool LatestApplicationPacketCarriesFin(QuicConnectionRuntime runtime)
    {
        QuicConnectionSentPacket packet = runtime.SendRuntime.SentPackets
            .Where(static entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .OrderByDescending(static entry => entry.Key.PacketNumber)
            .Select(static entry => entry.Value)
            .FirstOrDefault();

        return PacketCarriesFin(packet);
    }

    private static ulong GetLatestApplicationPacketNumber(QuicConnectionRuntime runtime)
        => runtime.SendRuntime.SentPackets
            .Where(static entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .Max(static entry => entry.Key.PacketNumber);

    private static bool ApplicationPacketWithFinWasSentAfter(
        QuicConnectionRuntime runtime,
        ulong packetNumber)
        => runtime.SendRuntime.SentPackets
            .Where(entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Key.PacketNumber > packetNumber)
            .Select(static entry => entry.Value)
            .Any(PacketCarriesFin);

    private static bool PacketCarriesFin(QuicConnectionSentPacket packet)
    {
        ReadOnlySpan<byte> payload = packet.PlaintextPayload.Span;
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                if (streamFrame.IsFin)
                {
                    return true;
                }

                offset += streamFrame.ConsumedLength;
                continue;
            }

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryConsumeAckFrame(remaining, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            return false;
        }

        return false;
    }
}
