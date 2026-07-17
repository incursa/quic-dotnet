// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Sockets;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures the steady-state socket bookkeeping required for the current non-ECT send path.
/// </summary>
[MemoryDiagnoser]
public class QuicSocketEcnControlBenchmarks
{
    private Socket socket = null!;

    /// <summary>
    /// Creates a representative IPv4 UDP socket.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    }

    /// <summary>
    /// Releases the benchmark socket.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        socket.Dispose();
    }

    /// <summary>
    /// Applies the marking emitted while receive-side ECN metadata is unavailable.
    /// </summary>
    [Benchmark]
    public bool ApplyNotEct()
        => QuicSocketEcnControl.TrySetEcnMarkingIfPossible(socket, QuicEcnMarking.NotEct);
}
