// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the delayed application-send queue ordering used by the runtime when queued stream writes are flushed.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationSendPriorityBenchmarks
{
    private PendingApplicationSendRequest[] mixedPriorityQueuedWrites = [];
    private PendingApplicationSendRequest[] equalPriorityQueuedWrites = [];

    /// <summary>
    /// Prepares representative queued writes with mixed priorities and equal-priority FIFO tie cases.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        mixedPriorityQueuedWrites =
        [
            new PendingApplicationSendRequest(0, 11, 0, [0x11, 0x12, 0x13], 3),
            new PendingApplicationSendRequest(1, 13, 10, [0x21, 0x22, 0x23], 3),
            new PendingApplicationSendRequest(2, 15, 5, [0x31, 0x32, 0x33], 3),
            new PendingApplicationSendRequest(3, 17, 10, [0x41, 0x42, 0x43], 3),
        ];

        equalPriorityQueuedWrites =
        [
            new PendingApplicationSendRequest(0, 21, 7, [0x51, 0x52], 2),
            new PendingApplicationSendRequest(1, 23, 7, [0x61, 0x62], 2),
            new PendingApplicationSendRequest(2, 25, 7, [0x71, 0x72], 2),
            new PendingApplicationSendRequest(3, 27, 7, [0x81, 0x82], 2),
        ];
    }

    /// <summary>
    /// Measures ordering the delayed send queue when priorities differ.
    /// </summary>
    [Benchmark]
    public ulong SortQueuedApplicationSendsByPriorityThenSequence()
    {
        PendingApplicationSendRequest[] queuedWrites =
            (PendingApplicationSendRequest[])mixedPriorityQueuedWrites.Clone();

        Array.Sort(queuedWrites, QuicApplicationSendQueue.ComparePendingApplicationSendRequests);
        return queuedWrites[0].StreamId ^ queuedWrites[^1].StreamId;
    }

    /// <summary>
    /// Measures ordering the delayed send queue when priorities are equal and FIFO becomes the tiebreaker.
    /// </summary>
    [Benchmark]
    public ulong SortQueuedApplicationSendsWithEqualPriorityPreservesFifoOrder()
    {
        PendingApplicationSendRequest[] queuedWrites =
            (PendingApplicationSendRequest[])equalPriorityQueuedWrites.Clone();

        Array.Sort(queuedWrites, QuicApplicationSendQueue.ComparePendingApplicationSendRequests);
        return (ulong)queuedWrites[0].Sequence + (ulong)queuedWrites[^1].Sequence;
    }
}
