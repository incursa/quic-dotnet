// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the socket receive paths available when a QUIC socket is bound to
/// one concrete local address.
/// </summary>
[MemoryDiagnoser]
public class QuicSocketReceivePathBenchmarks
{
    private readonly byte[] sendBuffer = new byte[1200];
    private readonly byte[] receiveBuffer = new byte[4096];
    private Socket sender = null!;
    private Socket receiver = null!;
    private EndPoint receiverEndPoint = null!;
    private QuicReusableReceiveEndPoint messageRemoteEndPoint = null!;
    private QuicReusableReceiveEndPoint remoteEndPoint = null!;
    private QuicReusableReceiveEndPoint socketAddressRemoteEndPoint = null!;

    /// <summary>
    /// Creates one concrete-bound loopback UDP path shared by both cases.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        receiverEndPoint = receiver.LocalEndPoint!;
        QuicSocketPacketInformationControl.TryEnablePacketInformationIfPossible(receiver);
        messageRemoteEndPoint = new QuicReusableReceiveEndPoint(AddressFamily.InterNetwork);
        remoteEndPoint = new QuicReusableReceiveEndPoint(AddressFamily.InterNetwork);
        socketAddressRemoteEndPoint = new QuicReusableReceiveEndPoint(AddressFamily.InterNetwork);
    }

    /// <summary>
    /// Releases the sockets after each benchmark case.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        sender.Dispose();
        receiver.Dispose();
    }

    /// <summary>
    /// Measures the ancillary-data receive path required by wildcard bindings.
    /// </summary>
    [Benchmark(Baseline = true)]
    public async ValueTask<int> ReceiveMessageFromAsync()
    {
        messageRemoteEndPoint.PrepareForReceive();
        sender.SendTo(sendBuffer, SocketFlags.None, receiverEndPoint);
        SocketReceiveMessageFromResult result = await receiver.ReceiveMessageFromAsync(
            receiveBuffer,
            SocketFlags.None,
            messageRemoteEndPoint);
        return result.ReceivedBytes;
    }

    /// <summary>
    /// Measures the lower-metadata receive path used by concrete bindings.
    /// </summary>
    [Benchmark]
    public async ValueTask<int> ReceiveFromAsync()
    {
        remoteEndPoint.PrepareForReceive();
        sender.SendTo(sendBuffer, SocketFlags.None, receiverEndPoint);
        SocketReceiveFromResult result = await receiver.ReceiveFromAsync(
            receiveBuffer,
            SocketFlags.None,
            remoteEndPoint);
        return result.ReceivedBytes;
    }

    /// <summary>
    /// Measures the reusable socket-address receive path used by concrete bindings.
    /// </summary>
    [Benchmark]
    public async ValueTask<int> ReceiveFromSocketAddressAsync()
    {
        sender.SendTo(sendBuffer, SocketFlags.None, receiverEndPoint);
        int receivedBytes = await receiver.ReceiveFromAsync(
            receiveBuffer,
            SocketFlags.None,
            socketAddressRemoteEndPoint.ReceiveAddress);
        GC.KeepAlive(socketAddressRemoteEndPoint.ResolveReceivedEndPoint());
        return receivedBytes;
    }
}
