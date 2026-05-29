// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks stream-id materialization for delayed application-send batches.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationSendDistinctStreamIdBenchmarks
{
    private PendingApplicationSendRequest[] uniqueQueuedWrites = [];

    /// <summary>
    /// Gets or sets the number of queued writes in the selected application-send batch.
    /// </summary>
    [Params(8, 128, 512)]
    public int QueuedWriteCount { get; set; }

    /// <summary>
    /// Prepares a worst-case distinct-stream batch where every selected write belongs to a different stream.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        uniqueQueuedWrites = new PendingApplicationSendRequest[QueuedWriteCount];
        for (int index = 0; index < uniqueQueuedWrites.Length; index++)
        {
            uniqueQueuedWrites[index] = new PendingApplicationSendRequest(
                index,
                (ulong)index * 4,
                Priority: 0,
                StreamPayload: [0x01],
                StreamPayloadLength: 1);
        }
    }

    /// <summary>
    /// Measures distinct stream-id extraction for selected queued application sends.
    /// </summary>
    [Benchmark]
    public ulong[] BuildDistinctStreamIdsForUniqueQueuedWrites()
        => QuicApplicationSendQueue.BuildDistinctStreamIds(uniqueQueuedWrites);
}
