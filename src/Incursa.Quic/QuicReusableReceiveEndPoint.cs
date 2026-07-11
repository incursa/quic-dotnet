// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic;

/// <summary>
/// Supplies reusable socket-address storage to a serial <see cref="Socket.ReceiveMessageFromAsync(Memory{byte}, SocketFlags, EndPoint, CancellationToken)" /> loop.
/// </summary>
internal sealed class QuicReusableReceiveEndPoint : IPEndPoint
{
    private const int MaxCachedPeers = 4096;

    // Socket.ReceiveMessageFromAsync asks for a receive buffer first. Its completion path then
    // serializes the endpoint again to compare the received peer with the previous peer.
    private readonly SocketAddress receiveAddress;
    private readonly SocketAddress comparisonAddress;
    private readonly Dictionary<SocketAddress, IPEndPoint> receivedPeers = [];
    private bool serializeReceiveAddress = true;

    internal QuicReusableReceiveEndPoint(AddressFamily addressFamily)
        : base(GetWildcardAddress(addressFamily), 0)
    {
        receiveAddress = base.Serialize();
        comparisonAddress = base.Serialize();
    }

    /// <summary>
    /// Resets serialization state before starting the next serial receive operation.
    /// </summary>
    internal void PrepareForReceive()
    {
        serializeReceiveAddress = true;
    }

    internal SocketAddress ReceiveAddress => receiveAddress;

    internal int CachedPeerCount => receivedPeers.Count;

    internal IPEndPoint ResolveReceivedEndPoint()
    {
        if (receivedPeers.TryGetValue(receiveAddress, out IPEndPoint? receivedEndPoint))
        {
            return receivedEndPoint;
        }

        receivedEndPoint = (IPEndPoint)base.Create(receiveAddress);
        if (receivedPeers.Count < MaxCachedPeers)
        {
            receivedPeers.Add(CloneSocketAddress(receiveAddress), receivedEndPoint);
        }

        return receivedEndPoint;
    }

    /// <inheritdoc />
    public override SocketAddress Serialize()
    {
        if (serializeReceiveAddress)
        {
            serializeReceiveAddress = false;
            return receiveAddress;
        }

        return comparisonAddress;
    }

    /// <inheritdoc />
    public override EndPoint Create(SocketAddress socketAddress)
    {
        ArgumentNullException.ThrowIfNull(socketAddress);

        IPEndPoint receivedEndPoint = (IPEndPoint)base.Create(socketAddress);
        Address = receivedEndPoint.Address;
        Port = receivedEndPoint.Port;
        // Peer changes are infrequent; keep the comparison buffer current so steady-state
        // receives avoid both SocketAddress serialization and endpoint reconstruction.
        CopySocketAddress(socketAddress, comparisonAddress);
        return this;
    }

    private static IPAddress GetWildcardAddress(AddressFamily addressFamily)
    {
        return addressFamily switch
        {
            AddressFamily.InterNetwork => IPAddress.Any,
            AddressFamily.InterNetworkV6 => IPAddress.IPv6Any,
            _ => throw new ArgumentOutOfRangeException(nameof(addressFamily), addressFamily, "Only IP address families are supported."),
        };
    }

    private static void CopySocketAddress(SocketAddress source, SocketAddress destination)
    {
        destination.Size = source.Size;
        for (int index = 0; index < source.Size; index++)
        {
            destination[index] = source[index];
        }
    }

    private static SocketAddress CloneSocketAddress(SocketAddress source)
    {
        SocketAddress clone = new(source.Family, source.Size);
        CopySocketAddress(source, clone);
        return clone;
    }
}
