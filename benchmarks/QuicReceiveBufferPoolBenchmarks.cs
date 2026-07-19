// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the fixed receive-ring ownership path used between socket receive and runtime shards.
/// </summary>
[MemoryDiagnoser]
public class QuicReceiveBufferPoolBenchmarks
{
    private const int OperationsPerBatch = 64;
    private QuicReceiveBufferPool pool = null!;

    /// <summary>
    /// Creates the same preallocated ring shape used by the socket hosts.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        pool = new QuicReceiveBufferPool(
            bufferSize: 65_535,
            ringSize: QuicReceiveBufferPool.DefaultRingSize,
            ownerName: "benchmark",
            preallocateRingBuffers: true);
    }

    /// <summary>
    /// Releases the diagnostic registration after the benchmark completes.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup() => pool.Dispose();

    /// <summary>
    /// Measures one ring rent and return without socket or packet-processing work.
    /// </summary>
    [Benchmark]
    public byte RentAndReturn()
    {
        using QuicReceiveBufferLease lease = pool.Rent();
        return lease.Buffer[0];
    }

    /// <summary>
    /// Measures a short receive burst while amortizing benchmark-call overhead.
    /// </summary>
    [Benchmark(OperationsPerInvoke = OperationsPerBatch)]
    public int RentAndReturnBatch()
    {
        int checksum = 0;
        for (int index = 0; index < OperationsPerBatch; index++)
        {
            using QuicReceiveBufferLease lease = pool.Rent();
            checksum += lease.Buffer[0];
        }

        return checksum;
    }
}
