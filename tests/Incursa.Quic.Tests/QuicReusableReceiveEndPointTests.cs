// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using Incursa.Quic;

namespace Incursa.Quic.Tests;

public sealed class QuicReusableReceiveEndPointTests
{
    [Fact]
    public async Task ReceiveMessageFromAsync_SameIpv4Peer_ReusesEndPoint()
    {
        using Socket receiver = CreateBoundSocket(AddressFamily.InterNetwork);
        using Socket sender = CreateBoundSocket(AddressFamily.InterNetwork);
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetwork);

        SocketReceiveMessageFromResult first = await SendAndReceiveAsync(sender, receiver, remoteEndPoint, 1);
        SocketReceiveMessageFromResult second = await SendAndReceiveAsync(sender, receiver, remoteEndPoint, 2);

        Assert.Same(remoteEndPoint, first.RemoteEndPoint);
        Assert.Same(remoteEndPoint, second.RemoteEndPoint);
        Assert.Equal(((IPEndPoint)sender.LocalEndPoint!).Address, remoteEndPoint.Address);
        Assert.Equal(((IPEndPoint)sender.LocalEndPoint!).Port, remoteEndPoint.Port);
    }

    [Fact]
    public async Task ReceiveMessageFromAsync_DifferentIpv4Peers_UpdatesReusedEndPoint()
    {
        using Socket receiver = CreateBoundSocket(AddressFamily.InterNetwork);
        using Socket firstSender = CreateBoundSocket(AddressFamily.InterNetwork);
        using Socket secondSender = CreateBoundSocket(AddressFamily.InterNetwork);
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetwork);

        SocketReceiveMessageFromResult first = await SendAndReceiveAsync(firstSender, receiver, remoteEndPoint, 1);
        int firstPort = ((IPEndPoint)firstSender.LocalEndPoint!).Port;
        Assert.Equal(firstPort, remoteEndPoint.Port);

        SocketReceiveMessageFromResult second = await SendAndReceiveAsync(secondSender, receiver, remoteEndPoint, 2);

        Assert.Same(remoteEndPoint, first.RemoteEndPoint);
        Assert.Same(remoteEndPoint, second.RemoteEndPoint);
        Assert.NotEqual(firstPort, remoteEndPoint.Port);
        Assert.Equal(((IPEndPoint)secondSender.LocalEndPoint!).Port, remoteEndPoint.Port);
    }

    [Fact]
    public async Task ReceiveFromAsync_SocketAddress_ReusesCachedIpv4PeerEndPoint()
    {
        using Socket receiver = CreateBoundSocket(AddressFamily.InterNetwork);
        using Socket sender = CreateBoundSocket(AddressFamily.InterNetwork);
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetwork);

        IPEndPoint first = await SendAndReceiveSocketAddressAsync(sender, receiver, remoteEndPoint, 1);
        IPEndPoint second = await SendAndReceiveSocketAddressAsync(sender, receiver, remoteEndPoint, 2);

        Assert.Same(first, second);
        Assert.Equal(sender.LocalEndPoint, first);
    }

    [Fact]
    public async Task ReceiveFromAsync_SocketAddress_CachesDistinctIpv4Peers()
    {
        using Socket receiver = CreateBoundSocket(AddressFamily.InterNetwork);
        using Socket firstSender = CreateBoundSocket(AddressFamily.InterNetwork);
        using Socket secondSender = CreateBoundSocket(AddressFamily.InterNetwork);
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetwork);

        IPEndPoint first = await SendAndReceiveSocketAddressAsync(firstSender, receiver, remoteEndPoint, 1);
        IPEndPoint second = await SendAndReceiveSocketAddressAsync(secondSender, receiver, remoteEndPoint, 2);
        IPEndPoint firstAgain = await SendAndReceiveSocketAddressAsync(firstSender, receiver, remoteEndPoint, 3);

        Assert.NotSame(first, second);
        Assert.Same(first, firstAgain);
        Assert.Equal(firstSender.LocalEndPoint, first);
        Assert.Equal(secondSender.LocalEndPoint, second);
    }

    [Fact]
    public async Task ReceiveFromAsync_SocketAddress_ReusesCachedIpv6PeerEndPoint()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using Socket receiver = CreateBoundSocket(AddressFamily.InterNetworkV6);
        using Socket sender = CreateBoundSocket(AddressFamily.InterNetworkV6);
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetworkV6);

        IPEndPoint first = await SendAndReceiveSocketAddressAsync(sender, receiver, remoteEndPoint, 1);
        IPEndPoint second = await SendAndReceiveSocketAddressAsync(sender, receiver, remoteEndPoint, 2);

        Assert.Same(first, second);
        Assert.Equal(sender.LocalEndPoint, first);
    }

    [Fact]
    public async Task ReceiveFromAsync_SocketAddress_PreservesDualModeIpv4MappedPeer()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using Socket receiver = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp)
        {
            DualMode = true,
        };
        receiver.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        using Socket sender = CreateBoundSocket(AddressFamily.InterNetwork);
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetworkV6);
        IPEndPoint receiverIpv4EndPoint = new(IPAddress.Loopback, ((IPEndPoint)receiver.LocalEndPoint!).Port);

        await sender.SendToAsync(new byte[] { 1 }, SocketFlags.None, receiverIpv4EndPoint);
        byte[] buffer = new byte[1];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int receivedBytes = await receiver.ReceiveFromAsync(
            buffer,
            SocketFlags.None,
            remoteEndPoint.ReceiveAddress,
            timeout.Token);
        IPEndPoint receivedFrom = remoteEndPoint.ResolveReceivedEndPoint();

        Assert.Equal(1, receivedBytes);
        Assert.True(receivedFrom.Address.IsIPv4MappedToIPv6);
        Assert.Equal(((IPEndPoint)sender.LocalEndPoint!).Port, receivedFrom.Port);
    }

    [Fact]
    public void ResolveReceivedEndPoint_CacheIsBoundedAndUncachedPeersRemainCorrect()
    {
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetwork);
        for (int port = 1; port <= 4096; port++)
        {
            CopySocketAddress(new IPEndPoint(IPAddress.Loopback, port).Serialize(), remoteEndPoint.ReceiveAddress);
            Assert.Equal(port, remoteEndPoint.ResolveReceivedEndPoint().Port);
        }

        CopySocketAddress(new IPEndPoint(IPAddress.Loopback, 4097).Serialize(), remoteEndPoint.ReceiveAddress);
        IPEndPoint firstUncached = remoteEndPoint.ResolveReceivedEndPoint();
        IPEndPoint secondUncached = remoteEndPoint.ResolveReceivedEndPoint();

        Assert.Equal(4096, remoteEndPoint.CachedPeerCount);
        Assert.Equal(4097, firstUncached.Port);
        Assert.Equal(4097, secondUncached.Port);
        Assert.NotSame(firstUncached, secondUncached);
    }

    [Fact]
    public async Task ReceiveMessageFromAsync_Ipv6Peer_ReusesEndPoint()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using Socket receiver = CreateBoundSocket(AddressFamily.InterNetworkV6);
        using Socket sender = CreateBoundSocket(AddressFamily.InterNetworkV6);
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetworkV6);

        SocketReceiveMessageFromResult result = await SendAndReceiveAsync(sender, receiver, remoteEndPoint, 1);

        Assert.Same(remoteEndPoint, result.RemoteEndPoint);
        Assert.Equal(IPAddress.IPv6Loopback, remoteEndPoint.Address);
        Assert.Equal(((IPEndPoint)sender.LocalEndPoint!).Port, remoteEndPoint.Port);
    }

    [Fact]
    public async Task ReceiveMessageFromAsync_DualModeIpv4Peer_ReusesIpv6EndPoint()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using Socket receiver = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp)
        {
            DualMode = true,
        };
        receiver.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        using Socket sender = CreateBoundSocket(AddressFamily.InterNetwork);
        QuicReusableReceiveEndPoint remoteEndPoint = new(AddressFamily.InterNetworkV6);
        IPEndPoint receiverIpv4EndPoint = new(IPAddress.Loopback, ((IPEndPoint)receiver.LocalEndPoint!).Port);

        await sender.SendToAsync(new byte[] { 1 }, SocketFlags.None, receiverIpv4EndPoint);
        byte[] buffer = new byte[1];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        remoteEndPoint.PrepareForReceive();
        SocketReceiveMessageFromResult result = await receiver.ReceiveMessageFromAsync(
            buffer,
            SocketFlags.None,
            remoteEndPoint,
            timeout.Token);

        Assert.Same(remoteEndPoint, result.RemoteEndPoint);
        Assert.True(remoteEndPoint.Address.IsIPv4MappedToIPv6);
        Assert.Equal(((IPEndPoint)sender.LocalEndPoint!).Port, remoteEndPoint.Port);
    }

    [Theory]
    [InlineData(AddressFamily.Unspecified)]
    [InlineData(AddressFamily.Unix)]
    public void Constructor_NonIpAddressFamily_Throws(AddressFamily addressFamily)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicReusableReceiveEndPoint(addressFamily));
    }

    private static Socket CreateBoundSocket(AddressFamily addressFamily)
    {
        IPAddress loopback = addressFamily == AddressFamily.InterNetworkV6
            ? IPAddress.IPv6Loopback
            : IPAddress.Loopback;
        Socket socket = new(addressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(loopback, 0));
        return socket;
    }

    private static async Task<SocketReceiveMessageFromResult> SendAndReceiveAsync(
        Socket sender,
        Socket receiver,
        QuicReusableReceiveEndPoint remoteEndPoint,
        byte value)
    {
        await sender.SendToAsync(new byte[] { value }, SocketFlags.None, receiver.LocalEndPoint!);

        byte[] buffer = new byte[1];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        remoteEndPoint.PrepareForReceive();
        SocketReceiveMessageFromResult result = await receiver.ReceiveMessageFromAsync(
            buffer,
            SocketFlags.None,
            remoteEndPoint,
            timeout.Token);

        Assert.Equal(1, result.ReceivedBytes);
        Assert.Equal(value, buffer[0]);
        return result;
    }

    private static async Task<IPEndPoint> SendAndReceiveSocketAddressAsync(
        Socket sender,
        Socket receiver,
        QuicReusableReceiveEndPoint remoteEndPoint,
        byte value)
    {
        await sender.SendToAsync(new byte[] { value }, SocketFlags.None, receiver.LocalEndPoint!);

        byte[] buffer = new byte[1];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int receivedBytes = await receiver.ReceiveFromAsync(
            buffer,
            SocketFlags.None,
            remoteEndPoint.ReceiveAddress,
            timeout.Token);

        Assert.Equal(1, receivedBytes);
        Assert.Equal(value, buffer[0]);
        return remoteEndPoint.ResolveReceivedEndPoint();
    }

    private static void CopySocketAddress(SocketAddress source, SocketAddress destination)
    {
        destination.Size = source.Size;
        for (int index = 0; index < source.Size; index++)
        {
            destination[index] = source[index];
        }
    }
}
