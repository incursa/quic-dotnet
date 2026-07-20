// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures the connection-local adaptive application-datagram batch policy decision.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationDatagramBatchPolicyBenchmarks
{
    private IQuicApplicationDatagramBatchPolicy sparsePolicy = null!;
    private IQuicApplicationDatagramBatchPolicy promotedPolicy = null!;

    /// <summary>
    /// Creates stable sparse and promoted policy states outside measurement.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        sparsePolicy = new QuicAdaptiveApplicationDatagramBatchPolicy();
        QuicAdaptiveApplicationDatagramBatchPolicy promoted = new();
        _ = promoted.ShouldBuildBatch(QuicConnectionRuntime.HostedApplicationDatagramBatchCapacity);
        _ = promoted.ShouldBuildBatch(QuicConnectionRuntime.HostedApplicationDatagramBatchCapacity);
        promotedPolicy = promoted;
    }

    /// <summary>
    /// Measures the equivalent direct low-pressure comparison.
    /// </summary>
    [Benchmark(Baseline = true)]
    public bool DirectSparseDecision()
        => 1 < QuicConnectionRuntime.HostedApplicationDatagramBatchCapacity;

    /// <summary>
    /// Measures the shipped sparse client policy path.
    /// </summary>
    [Benchmark]
    public bool AdaptiveSparseDecision()
        => sparsePolicy.ShouldBuildBatch(queuedStreamCount: 1);

    /// <summary>
    /// Measures the stable one-way promoted decision.
    /// </summary>
    [Benchmark]
    public bool AdaptivePromotedDecision()
        => promotedPolicy.ShouldBuildBatch(queuedStreamCount: 1);
}

/// <summary>
/// Measures the bounded distinct-stream pressure observation used by the adaptive policy.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationDatagramPressureBenchmarks
{
    private QuicApplicationSendQueue sparseQueue = null!;
    private QuicApplicationSendQueue pressuredQueue = null!;

    /// <summary>
    /// Creates stable sparse and pressured queues outside measurement.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        sparseQueue = new QuicApplicationSendQueue();
        pressuredQueue = new QuicApplicationSendQueue();
        for (int index = 0; index < 32; index++)
        {
            sparseQueue.Enqueue(4, 0, QuicBufferPool.RentBytes(1), 1);
            pressuredQueue.Enqueue((ulong)index, 0, QuicBufferPool.RentBytes(1), 1);
        }
    }

    /// <summary>
    /// Returns pooled queue owners after measurement.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        sparseQueue.Clear();
        pressuredQueue.Clear();
    }

    /// <summary>
    /// Measures a long queue containing writes for one stream.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int CountOneDistinctStream()
    {
        Span<ulong> distinctStreamIds = stackalloc ulong[QuicConnectionRuntime.HostedApplicationDatagramBatchCapacity];
        return sparseQueue.CountDistinctStreamIdsUpTo(distinctStreamIds);
    }

    /// <summary>
    /// Measures early exit at the bounded pressure threshold.
    /// </summary>
    [Benchmark]
    public int CountStreamsToPressureBound()
    {
        Span<ulong> distinctStreamIds = stackalloc ulong[QuicConnectionRuntime.HostedApplicationDatagramBatchCapacity];
        return pressuredQueue.CountDistinctStreamIdsUpTo(distinctStreamIds);
    }
}
