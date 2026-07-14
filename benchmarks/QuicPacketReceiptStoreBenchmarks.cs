// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the current sorted receipt ledger with pooled ordered storage over a populate-and-retire lifecycle.
/// </summary>
[MemoryDiagnoser]
public class QuicPacketReceiptStoreBenchmarks
{
    /// <summary>
    /// Gets or sets the retained packet count populated per operation.
    /// </summary>
    [Params(128, 1_024, 2_400)]
    public int ReceiptCount { get; set; }

    /// <summary>
    /// Populates and retires a contiguous middle range using the current sorted-list shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int SortedListLifecycle()
    {
        SortedList<ulong, QuicPacketReceipt> receipts = new(32);
        for (int index = 0; index < ReceiptCount; index++)
        {
            receipts.Add((ulong)index, CreateReceipt(index));
        }

        int firstRemoved = ReceiptCount / 4;
        int lastRemoved = (ReceiptCount * 3) / 4;
        for (int packetNumber = firstRemoved; packetNumber <= lastRemoved; packetNumber++)
        {
            receipts.Remove((ulong)packetNumber);
        }

        return receipts.Count;
    }

    /// <summary>
    /// Populates and retires the same range using pooled ordered receipt storage.
    /// </summary>
    [Benchmark]
    public int PooledStoreLifecycle()
    {
        QuicPacketReceiptStore receipts = new(initialCapacity: 32);
        try
        {
            for (int index = 0; index < ReceiptCount; index++)
            {
                receipts.Set((ulong)index, CreateReceipt(index));
            }

            receipts.RemoveRange((ulong)(ReceiptCount / 4), (ulong)((ReceiptCount * 3) / 4));
            return receipts.Count;
        }
        finally
        {
            receipts.ClearAndReturnStorage();
        }
    }

    private static QuicPacketReceipt CreateReceipt(int index)
        => new((ulong)index, BufferingDelayMicros: 0, AckEliciting: true);
}
