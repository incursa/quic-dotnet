// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks byte-range-set snapshot restore with disjoint ranges.
/// </summary>
[MemoryDiagnoser]
public class QuicByteRangeSetRestoreBenchmarks
{
    private QuicByteRangeSetSnapshot snapshot;

    /// <summary>
    /// Gets or sets the number of ranges restored from the snapshot.
    /// </summary>
    [Params(1, 16, 128)]
    public int RangeCount { get; set; }

    /// <summary>
    /// Prepares a snapshot containing non-coalesced ranges.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        QuicByteRange[] ranges = new QuicByteRange[RangeCount];
        for (int index = 0; index < ranges.Length; index++)
        {
            ulong start = (ulong)index * 2;
            ranges[index] = new QuicByteRange(start, start + 1);
        }

        snapshot = new QuicByteRangeSetSnapshot(ranges, (ulong)ranges.Length);
    }

    /// <summary>
    /// Measures the prior restore shape that let the list grow incrementally.
    /// </summary>
    [Benchmark(Baseline = true)]
    public ulong RestoreWithoutPreSizing()
    {
        OldByteRangeSet set = new();
        set.Restore(snapshot);
        return set.TotalLength;
    }

    /// <summary>
    /// Measures restore after pre-sizing the backing list before replaying ranges.
    /// </summary>
    [Benchmark]
    public ulong RestoreWithPreSizing()
    {
        QuicByteRangeSet set = new();
        set.Restore(snapshot);
        return set.TotalLength;
    }

    private sealed class OldByteRangeSet
    {
        private readonly List<Range> ranges = [];

        internal ulong TotalLength { get; private set; }

        internal void Restore(QuicByteRangeSetSnapshot snapshot)
        {
            ranges.Clear();
            for (int index = 0; index < snapshot.Ranges.Length; index++)
            {
                QuicByteRange range = snapshot.Ranges[index];
                ranges.Add(new Range(range.Start, range.End));
            }

            TotalLength = snapshot.TotalLength;
        }

        private readonly record struct Range(ulong Start, ulong End);
    }
}
