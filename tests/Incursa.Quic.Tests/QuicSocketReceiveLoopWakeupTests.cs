// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class QuicSocketReceiveLoopWakeupTests
{
    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public async Task TryWake_UnblocksPendingReceiveWithoutCancellation(AddressFamily addressFamily)
    {
        if (addressFamily == AddressFamily.InterNetworkV6 && !Socket.OSSupportsIPv6)
        {
            return;
        }

        using Socket socket = new(addressFamily, SocketType.Dgram, ProtocolType.Udp);
        if (addressFamily == AddressFamily.InterNetworkV6)
        {
            socket.DualMode = true;
        }

        IPAddress anyAddress = addressFamily == AddressFamily.InterNetworkV6
            ? IPAddress.IPv6Any
            : IPAddress.Any;
        socket.Bind(new IPEndPoint(anyAddress, 0));

        byte[] buffer = new byte[1];
        EndPoint remoteEndPoint = new IPEndPoint(anyAddress, 0);
        ValueTask<SocketReceiveMessageFromResult> receiveTask = socket.ReceiveMessageFromAsync(
            buffer.AsMemory(),
            SocketFlags.None,
            remoteEndPoint,
            CancellationToken.None);

        Assert.True(QuicSocketReceiveLoopWakeup.TryWake(socket));

        SocketReceiveMessageFromResult result = await receiveTask.AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, result.ReceivedBytes);
    }
}
