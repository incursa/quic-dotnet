// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares fixed ACK receipt map populations using the former per-receipt ECN snapshot and compact value layouts.
/// </summary>
[MemoryDiagnoser]
public class QuicPacketReceiptValueBenchmarks
{
    /// <summary>
    /// Gets or sets the number of packet receipts populated per operation.
    /// </summary>
    [Params(32, 128, 1_024)]
    public int ReceiptCount { get; set; }

    /// <summary>
    /// Populates a sorted map using the former 48-byte per-receipt ECN snapshot shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PopulateSortedListWithFormerValue()
    {
        SortedList<ulong, FormerPacketReceipt> receipts = new(32);
        for (int index = 0; index < ReceiptCount; index++)
        {
            receipts.Add(
                (ulong)index,
                new FormerPacketReceipt((ulong)index, 0, AckEliciting: true, EcnCounts: default));
        }

        return receipts.Count;
    }

    /// <summary>
    /// Populates a sorted map using the packed production receipt value.
    /// </summary>
    [Benchmark]
    public int PopulateSortedListWithPackedValue()
    {
        SortedList<ulong, QuicPacketReceipt> receipts = new(32);
        for (int index = 0; index < ReceiptCount; index++)
        {
            receipts.Add(
                (ulong)index,
                new QuicPacketReceipt((ulong)index, 0, AckEliciting: true));
        }

        return receipts.Count;
    }

    private readonly record struct FormerPacketReceipt(
        ulong ReceivedAtMicros,
        ulong BufferingDelayMicros,
        bool AckEliciting,
        QuicEcnCounts EcnCounts);
}
