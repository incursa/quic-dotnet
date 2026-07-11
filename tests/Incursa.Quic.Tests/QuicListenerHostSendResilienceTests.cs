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
                    Volatile.Write(ref droppedFin, 1);

                    throw new SocketException((int)SocketError.NoBufferSpaceAvailable);
                }

                if (Volatile.Read(ref droppedFin) != 0 && carriesFin)
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

    private static bool LatestApplicationPacketCarriesFin(QuicConnectionRuntime runtime)
    {
        QuicConnectionSentPacket packet = runtime.SendRuntime.SentPackets
            .Where(static entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .OrderByDescending(static entry => entry.Key.PacketNumber)
            .Select(static entry => entry.Value)
            .FirstOrDefault();

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
