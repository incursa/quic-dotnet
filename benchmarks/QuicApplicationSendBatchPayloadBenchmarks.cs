// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares multi-write application payload coalescing with a fresh array versus pooled ownership.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationSendBatchPayloadBenchmarks
{
    private PendingApplicationSendRequest[] writes = [];

    /// <summary>
    /// Gets or sets the number of queued writes in the selected batch.
    /// </summary>
    [Params(8, 64)]
    public int WriteCount { get; set; }

    /// <summary>
    /// Gets or sets the payload size of each queued write.
    /// </summary>
    [Params(128)]
    public int PayloadLength { get; set; }

    /// <summary>
    /// Prepares representative queued write payloads.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        writes = new PendingApplicationSendRequest[WriteCount];
        for (int index = 0; index < writes.Length; index++)
        {
            byte[] payload = new byte[PayloadLength];
            payload.AsSpan().Fill((byte)(index + 1));
            writes[index] = new PendingApplicationSendRequest(
                Sequence: index,
                StreamId: (ulong)index * 4,
                Priority: index % 4,
                StreamPayload: payload,
                StreamPayloadLength: payload.Length);
        }
    }

    /// <summary>
    /// Baseline equivalent of the previous multi-write combine path.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int FreshArrayPerBatch()
    {
        int combinedPayloadLength = GetCombinedPayloadLength(writes);
        byte[] combinedPayload = new byte[combinedPayloadLength];
        CopyWrites(writes, combinedPayload);
        return Consume(combinedPayload, combinedPayloadLength);
    }

    /// <summary>
    /// Measures the patched path that rents the combined payload buffer.
    /// </summary>
    [Benchmark]
    public int PooledArrayPerBatch()
    {
        int combinedPayloadLength = GetCombinedPayloadLength(writes);
        byte[] combinedPayload = QuicBufferPool.RentBytes(combinedPayloadLength);
        try
        {
            CopyWrites(writes, combinedPayload);
            return Consume(combinedPayload, combinedPayloadLength);
        }
        finally
        {
            QuicBufferPool.ReturnBytes(combinedPayload);
        }
    }

    private static int GetCombinedPayloadLength(ReadOnlySpan<PendingApplicationSendRequest> selectedWrites)
    {
        int combinedPayloadLength = 0;
        foreach (PendingApplicationSendRequest queuedWrite in selectedWrites)
        {
            combinedPayloadLength = checked(combinedPayloadLength + queuedWrite.StreamPayloadLength);
        }

        return combinedPayloadLength;
    }

    private static void CopyWrites(ReadOnlySpan<PendingApplicationSendRequest> selectedWrites, Span<byte> destination)
    {
        int copyOffset = 0;
        foreach (PendingApplicationSendRequest queuedWrite in selectedWrites)
        {
            queuedWrite.StreamPayload.AsSpan(0, queuedWrite.StreamPayloadLength)
                .CopyTo(destination[copyOffset..]);
            copyOffset += queuedWrite.StreamPayloadLength;
        }
    }

    private static int Consume(ReadOnlySpan<byte> payload, int length)
    {
        return length ^ payload[0] ^ payload[length - 1];
    }
}
