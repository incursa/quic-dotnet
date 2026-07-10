// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Isolates the endpoint serialization performed by <c>Socket.ReceiveMessageFromAsync</c> and
/// the peer comparison performed by its <c>SocketAsyncEventArgs</c> completion path.
/// </summary>
[MemoryDiagnoser]
public class QuicReceiveEndPointBenchmarks
{
    private readonly SocketAddress receivedAddress = new IPEndPoint(IPAddress.Loopback, 443).Serialize();
    private IPEndPoint standardEndPoint = new(IPAddress.Loopback, 443);
    private QuicReusableReceiveEndPoint reusableEndPoint = new(AddressFamily.InterNetwork);

    /// <summary>
    /// Primes the reusable endpoint with the representative peer address.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        SimulateReusableReceive();
    }

    /// <summary>
    /// Models the socket-address creation performed for a standard <see cref="IPEndPoint" />.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int StandardIPEndPoint()
    {
        SocketAddress receiveBuffer = standardEndPoint.Serialize();
        CopySocketAddress(receivedAddress, receiveBuffer);
        if (!receiveBuffer.Equals(standardEndPoint.Serialize()))
        {
            standardEndPoint = (IPEndPoint)standardEndPoint.Create(receiveBuffer);
        }

        return standardEndPoint.Port;
    }

    /// <summary>
    /// Models the same operation with reusable receive and comparison socket-address storage.
    /// </summary>
    [Benchmark]
    public int ReusableIPEndPoint()
    {
        return SimulateReusableReceive();
    }

    private int SimulateReusableReceive()
    {
        reusableEndPoint.PrepareForReceive();
        SocketAddress receiveBuffer = reusableEndPoint.Serialize();
        CopySocketAddress(receivedAddress, receiveBuffer);
        if (!receiveBuffer.Equals(reusableEndPoint.Serialize()))
        {
            reusableEndPoint = (QuicReusableReceiveEndPoint)reusableEndPoint.Create(receiveBuffer);
        }

        return reusableEndPoint.Port;
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
