// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the ACK range-building walk over enumerables against direct indexed access on sorted receipts.
/// </summary>
[MemoryDiagnoser]
public class QuicAckGenerationStateRangeEnumerationBenchmarks
{
    private readonly SortedList<ulong, int> receipts = [];

    /// <summary>
    /// Gets or sets the number of received packet numbers to summarize into ranges.
    /// </summary>
    [Params(32, 128)]
    public int ReceiptCount { get; set; }

    /// <summary>
    /// Prepares a sorted packet-number set with contiguous numbers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        receipts.Clear();
        for (ulong packetNumber = 1; packetNumber <= (ulong)ReceiptCount; packetNumber++)
        {
            receipts.Add(packetNumber, unchecked((int)packetNumber));
        }
    }

    /// <summary>
    /// Baseline equivalent of the previous enumerable-based walk.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int BuildRangesViaEnumerable()
    {
        Span<PacketRange> ranges = stackalloc PacketRange[256];
        return BuildRangesEnumerable(receipts.Keys, ranges);
    }

    /// <summary>
    /// Measures the indexed sorted-list walk used by the production code.
    /// </summary>
    [Benchmark]
    public int BuildRangesViaSortedListKeys()
    {
        Span<PacketRange> ranges = stackalloc PacketRange[256];
        return BuildRangesDirect(receipts, ranges);
    }

    private static int BuildRangesEnumerable(IEnumerable<ulong> packetNumbers, Span<PacketRange> ranges)
    {
        using IEnumerator<ulong> enumerator = packetNumbers.GetEnumerator();
        if (!enumerator.MoveNext())
        {
            return 0;
        }

        int rangeCount = 0;
        ulong rangeStart = enumerator.Current;
        ulong rangeEnd = rangeStart;

        while (enumerator.MoveNext())
        {
            ulong packetNumber = enumerator.Current;
            if (rangeEnd != ulong.MaxValue && packetNumber == rangeEnd + 1)
            {
                rangeEnd = packetNumber;
                continue;
            }

            ranges[rangeCount++] = new PacketRange(rangeStart, rangeEnd);
            rangeStart = packetNumber;
            rangeEnd = packetNumber;
        }

        ranges[rangeCount++] = new PacketRange(rangeStart, rangeEnd);
        return rangeCount;
    }

    private static int BuildRangesDirect(SortedList<ulong, int> receipts, Span<PacketRange> ranges)
    {
        if (receipts.Count == 0)
        {
            return 0;
        }

        IList<ulong> packetNumbers = receipts.Keys;
        int rangeCount = 0;
        ulong rangeStart = packetNumbers[0];
        ulong rangeEnd = rangeStart;

        for (int index = 1; index < packetNumbers.Count; index++)
        {
            ulong packetNumber = packetNumbers[index];
            if (rangeEnd != ulong.MaxValue && packetNumber == rangeEnd + 1)
            {
                rangeEnd = packetNumber;
                continue;
            }

            ranges[rangeCount++] = new PacketRange(rangeStart, rangeEnd);
            rangeStart = packetNumber;
            rangeEnd = packetNumber;
        }

        ranges[rangeCount++] = new PacketRange(rangeStart, rangeEnd);
        return rangeCount;
    }

    private readonly record struct PacketRange(ulong Smallest, ulong Largest);
}
