// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class QuicSocketSendBatchTests
{
    [Fact]
    public void NativeCapabilityMatchesThePlatform()
    {
        Assert.Equal(OperatingSystem.IsLinux(), QuicSocketSendBatch.IsNativeSendMmsgSupported);
    }

    [Fact]
    public void Linux64NativeLayoutsMatchTheSendMmsgAbi()
    {
        if (!OperatingSystem.IsLinux() || IntPtr.Size != 8)
        {
            return;
        }

        Assert.Equal(16, QuicSocketSendBatch.NativeIovecSize);
        Assert.Equal(56, QuicSocketSendBatch.NativeMsghdrSize);
        Assert.Equal(64, QuicSocketSendBatch.NativeMmsghdrSize);
    }

    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public void SendBatchPreservesPayloadDestinationAndOrdering(AddressFamily addressFamily)
    {
        if (addressFamily == AddressFamily.InterNetworkV6 && !Socket.OSSupportsIPv6)
        {
            return;
        }

        using Socket receiverA = CreateReceiver(addressFamily, out IPEndPoint receiverAEndPoint);
        using Socket receiverB = CreateReceiver(addressFamily, out IPEndPoint receiverBEndPoint);
        using Socket sender = new(addressFamily, SocketType.Dgram, ProtocolType.Udp);

        SocketAddress receiverAAddress = receiverAEndPoint.Serialize();
        SocketAddress receiverBAddress = receiverBEndPoint.Serialize();

        QuicSocketSendBatchMessage[] messages =
        [
            new(new byte[] { 0x11, 0x12, 0x13 }, receiverAAddress),
            new(new byte[] { 0x21, 0x22, 0x23 }, receiverBAddress),
            new(new byte[] { 0x31, 0x32, 0x33 }, receiverAAddress),
            new(new byte[] { 0x41, 0x42, 0x43 }, receiverBAddress),
        ];

        QuicSocketSendBatchResult result = QuicSocketSendBatch.Send(sender, messages);

        Assert.Equal(messages.Length, result.SentMessages);
        Assert.Equal(12, result.SentBytes);
        Assert.Equal(QuicSocketSendBatch.IsNativeSendMmsgSupported, result.UsedNativeSendMmsg);

        Assert.Equal(new byte[] { 0x11, 0x12, 0x13 }, ReceiveDatagram(receiverA));
        Assert.Equal(new byte[] { 0x21, 0x22, 0x23 }, ReceiveDatagram(receiverB));
        Assert.Equal(new byte[] { 0x31, 0x32, 0x33 }, ReceiveDatagram(receiverA));
        Assert.Equal(new byte[] { 0x41, 0x42, 0x43 }, ReceiveDatagram(receiverB));
    }

    [Fact]
    public void SendBatchReturnsZeroWhenSocketIsDisposed()
    {
        Socket sender = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sender.Dispose();

        QuicSocketSendBatchMessage[] messages =
        [
            new(new byte[] { 0x01, 0x02, 0x03 }, new IPEndPoint(IPAddress.Loopback, 54321).Serialize()),
        ];

        QuicSocketSendBatchResult result = QuicSocketSendBatch.Send(sender, messages);

        Assert.Equal(0, result.SentMessages);
        Assert.Equal(0, result.SentBytes);
    }

    [Fact]
    public async Task SendBatchDoesNotUseARecycledDescriptorWhenSocketIsDisposedConcurrently()
    {
        using Socket receiver = CreateReceiver(AddressFamily.InterNetwork, out IPEndPoint receiverEndPoint);
        Socket sender = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        QuicSocketSendBatchMessage[] messages = Enumerable.Range(0, 64)
            .Select(index => new QuicSocketSendBatchMessage(new byte[] { (byte)index }, receiverEndPoint.Serialize()))
            .ToArray();

        Task<QuicSocketSendBatchResult> send = Task.Run(() => QuicSocketSendBatch.Send(sender, messages));
        sender.Dispose();
        QuicSocketSendBatchResult result = await send;

        Assert.InRange(result.SentMessages, 0, messages.Length);
        Assert.InRange(result.SentBytes, 0, messages.Length);
    }

    private static Socket CreateReceiver(AddressFamily addressFamily, out IPEndPoint localEndPoint)
    {
        Socket socket = new(addressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.ReceiveTimeout = (int)TimeSpan.FromSeconds(5).TotalMilliseconds;

        if (addressFamily == AddressFamily.InterNetworkV6)
        {
            socket.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        }
        else
        {
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        }

        localEndPoint = (IPEndPoint)socket.LocalEndPoint!;
        return socket;
    }

    private static byte[] ReceiveDatagram(Socket socket)
    {
        byte[] buffer = new byte[256];
        EndPoint remoteEndPoint = socket.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

        int bytesReceived = socket.ReceiveFrom(buffer, SocketFlags.None, ref remoteEndPoint);
        return buffer[..bytesReceived];
    }
}
