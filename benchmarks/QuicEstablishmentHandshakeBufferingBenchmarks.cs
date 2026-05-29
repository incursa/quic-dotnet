// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the ownership copies used when establishment Handshake packets are buffered for deferred retry.
/// </summary>
[MemoryDiagnoser]
public class QuicEstablishmentHandshakeBufferingBenchmarks
{
    private byte[] sourceConnectionId = [];
    private byte[] datagram = [];

    /// <summary>
    /// Gets or sets the protected datagram size buffered for deferred retry.
    /// </summary>
    [Params(256, 1200)]
    public int DatagramLength { get; set; }

    /// <summary>
    /// Prepares packet-shaped input buffers and warms the shared buffer pool.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        sourceConnectionId = Enumerable.Range(0, 8).Select(static value => (byte)value).ToArray();
        datagram = Enumerable.Range(0, DatagramLength).Select(static value => (byte)value).ToArray();

        byte[] sourceConnectionIdBuffer = QuicBufferPool.RentBytes(sourceConnectionId.Length);
        byte[] datagramBuffer = QuicBufferPool.RentBytes(datagram.Length);
        QuicBufferPool.ReturnBytes(sourceConnectionIdBuffer);
        QuicBufferPool.ReturnBytes(datagramBuffer);
    }

    /// <summary>
    /// Measures the prior shape that materialized exact arrays with <c>ToArray</c>.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int ToArrayCopies()
    {
        byte[] sourceConnectionIdCopy = sourceConnectionId.AsMemory().ToArray();
        byte[] datagramCopy = datagram.AsMemory().ToArray();
        return sourceConnectionIdCopy.Length + datagramCopy.Length;
    }

    /// <summary>
    /// Measures the pooled-copy shape now used by deferred establishment packet buffering.
    /// </summary>
    [Benchmark]
    public int PooledCopies()
    {
        byte[] sourceConnectionIdBuffer = QuicBufferPool.RentBytes(sourceConnectionId.Length);
        sourceConnectionId.CopyTo(sourceConnectionIdBuffer, 0);
        byte[] datagramBuffer = QuicBufferPool.RentBytes(datagram.Length);
        datagram.CopyTo(datagramBuffer, 0);
        int length = sourceConnectionId.Length + datagram.Length;
        QuicBufferPool.ReturnBytes(sourceConnectionIdBuffer);
        QuicBufferPool.ReturnBytes(datagramBuffer);
        return length;
    }
}
