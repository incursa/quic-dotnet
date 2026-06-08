// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks sorting materialization for delayed application-send batches.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationSendQueueSortingBenchmarks
{
    private QuicApplicationSendQueue queue = new();

    /// <summary>
    /// Gets or sets the number of pending writes waiting in the application-send queue.
    /// </summary>
    [Params(8, 128, 512)]
    public int QueuedWriteCount { get; set; }

    /// <summary>
    /// Prepares queued writes with mixed priorities and equal-priority FIFO cases.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        queue = new QuicApplicationSendQueue();
        for (int index = 0; index < QueuedWriteCount; index++)
        {
            int priority = index % 7;
            queue.Enqueue(
                (ulong)index * 4,
                priority,
                streamPayload: [(byte)index],
                streamPayloadLength: 1);
        }
    }

    /// <summary>
    /// Measures sorted queued-write materialization for a delayed application-send flush.
    /// </summary>
    [Benchmark]
    public long GetSortedQueuedWritesByPriorityThenSequence()
    {
        PendingApplicationSendRequest[] queuedWrites = queue.RentSortedQueuedWrites(out int queuedWriteCount);
        try
        {
            ReadOnlySpan<PendingApplicationSendRequest> sortedWrites = queuedWrites.AsSpan(0, queuedWriteCount);
            return sortedWrites[0].Sequence + sortedWrites[^1].Sequence;
        }
        finally
        {
            QuicApplicationSendQueue.ReturnRentedQueuedWrites(queuedWrites);
        }
    }

    /// <summary>
    /// Measures the fragmented-head fast path that only needs the next queued write.
    /// </summary>
    [Benchmark]
    public long GetNextQueuedWriteByPriorityThenSequence()
    {
        return queue.TryGetNextQueuedWrite(out PendingApplicationSendRequest queuedWrite)
            ? queuedWrite.Sequence + (long)queuedWrite.StreamId
            : 0;
    }
}
