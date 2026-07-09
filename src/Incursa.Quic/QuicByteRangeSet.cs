// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The stored ranges are kept normalized and coalesced so coverage math can rely on an
// ordered, non-overlapping shape; touching ranges stay merged to keep the representation compact.
// SEE: MeasureAdditionalCoverage and CoversPrefix
/// <summary>
/// Maintains a normalized, non-overlapping set of half-open byte ranges and tracks the total
/// amount of unique coverage across all stored ranges.
/// </summary>
internal sealed class QuicByteRangeSet
{
    // The common empty/single-range cases stay inline; multi-range state uses the same normalized list shape.
    private List<Range>? ranges;
    private Range singleRange;
    private bool hasSingleRange;

    /// <summary>
    /// Gets the total length of unique bytes represented by the stored ranges.
    /// </summary>
    public ulong TotalLength { get; private set; }

    /// <summary>
    /// Measures how many additional unique bytes would be covered by adding <paramref name="start" />
    /// through <paramref name="endExclusive" />.
    /// </summary>
    /// <param name="start">The inclusive starting offset.</param>
    /// <param name="endExclusive">The exclusive ending offset.</param>
    /// <returns>The number of bytes that are not already covered.</returns>
    public ulong MeasureAdditionalCoverage(ulong start, ulong endExclusive)
    {
        if (endExclusive <= start)
        {
            return 0;
        }

        if (ranges is List<Range> rangeList)
        {
            return MeasureAdditionalCoverage(rangeList, start, endExclusive);
        }

        return hasSingleRange
            ? MeasureAdditionalCoverage(singleRange, start, endExclusive)
            : endExclusive - start;
    }

    private static ulong MeasureAdditionalCoverage(List<Range> ranges, ulong start, ulong endExclusive)
    {
        ulong additional = 0;
        ulong cursor = start;

        foreach (Range range in ranges)
        {
            if (!MeasureRangeCoverageGap(range, endExclusive, ref cursor, ref additional))
            {
                break;
            }
        }

        AddTrailingGap(endExclusive, cursor, ref additional);
        return additional;
    }

    private static ulong MeasureAdditionalCoverage(Range range, ulong start, ulong endExclusive)
    {
        ulong additional = 0;
        ulong cursor = start;
        MeasureRangeCoverageGap(range, endExclusive, ref cursor, ref additional);
        AddTrailingGap(endExclusive, cursor, ref additional);
        return additional;
    }

    /// <summary>
    /// Adds the specified half-open byte range, merging overlaps and touching ranges.
    /// </summary>
    /// <param name="start">The inclusive starting offset.</param>
    /// <param name="endExclusive">The exclusive ending offset.</param>
    /// <returns>The number of previously uncovered bytes that were added.</returns>
    public ulong Add(ulong start, ulong endExclusive)
    {
        ulong additional = MeasureAdditionalCoverage(start, endExclusive);
        if (additional == 0)
        {
            return 0;
        }

        if (ranges is null)
        {
            AddInline(start, endExclusive);
            TotalLength += additional;
            return additional;
        }

        int insertIndex = 0;
        while (insertIndex < ranges.Count && ranges[insertIndex].End < start)
        {
            insertIndex++;
        }

        ulong mergedStart = start;
        ulong mergedEnd = endExclusive;
        while (insertIndex < ranges.Count && ranges[insertIndex].Start <= mergedEnd)
        {
            mergedStart = Math.Min(mergedStart, ranges[insertIndex].Start);
            mergedEnd = Math.Max(mergedEnd, ranges[insertIndex].End);
            ranges.RemoveAt(insertIndex);
        }

        ranges.Insert(insertIndex, new Range(mergedStart, mergedEnd));
        TotalLength += additional;
        return additional;
    }

    /// <summary>
    /// Determines whether the set covers every byte from offset 0 through <paramref name="endExclusive" />.
    /// </summary>
    /// <param name="endExclusive">The exclusive end offset of the prefix to test.</param>
    /// <returns><see langword="true" /> when the prefix is fully covered; otherwise, <see langword="false" />.</returns>
    public bool CoversPrefix(ulong endExclusive)
    {
        if (endExclusive == 0)
        {
            return true;
        }

        if (ranges is List<Range> rangeList)
        {
            return rangeList.Count > 0
                && rangeList[0].Start == 0
                && rangeList[0].End >= endExclusive;
        }

        return hasSingleRange
            && singleRange.Start == 0
            && singleRange.End >= endExclusive;
    }

    internal QuicByteRangeSetSnapshot CaptureSnapshot()
    {
        if (ranges is null)
        {
            if (!hasSingleRange)
            {
                return QuicByteRangeSetSnapshot.CreateEmpty(TotalLength);
            }

            return QuicByteRangeSetSnapshot.CreateSingle(
                new QuicByteRange(singleRange.Start, singleRange.End),
                TotalLength);
        }

        QuicByteRange[] snapshotRanges = new QuicByteRange[ranges.Count];
        for (int index = 0; index < ranges.Count; index++)
        {
            Range range = ranges[index];
            snapshotRanges[index] = new QuicByteRange(range.Start, range.End);
        }

        return new QuicByteRangeSetSnapshot(snapshotRanges, TotalLength);
    }

    internal void Restore(QuicByteRangeSetSnapshot snapshot)
    {
        if (snapshot.RangeCount == 0)
        {
            ranges = null;
            hasSingleRange = false;
            singleRange = default;
            TotalLength = snapshot.TotalLength;
            return;
        }

        if (snapshot.RangeCount == 1)
        {
            QuicByteRange range = snapshot.GetRange(0);
            ranges = null;
            singleRange = new Range(range.Start, range.End);
            hasSingleRange = true;
            TotalLength = snapshot.TotalLength;
            return;
        }

        ranges ??= new List<Range>(snapshot.RangeCount);
        ranges.Clear();
        ranges.EnsureCapacity(snapshot.RangeCount);
        for (int index = 0; index < snapshot.RangeCount; index++)
        {
            QuicByteRange range = snapshot.GetRange(index);
            ranges.Add(new Range(range.Start, range.End));
        }

        hasSingleRange = false;
        singleRange = default;
        TotalLength = snapshot.TotalLength;
    }

    private void AddInline(ulong start, ulong endExclusive)
    {
        if (!hasSingleRange)
        {
            singleRange = new Range(start, endExclusive);
            hasSingleRange = true;
            return;
        }

        if (endExclusive < singleRange.Start)
        {
            ranges = [new Range(start, endExclusive), singleRange];
            hasSingleRange = false;
            singleRange = default;
            return;
        }

        if (singleRange.End < start)
        {
            ranges = [singleRange, new Range(start, endExclusive)];
            hasSingleRange = false;
            singleRange = default;
            return;
        }

        singleRange = new Range(
            Math.Min(singleRange.Start, start),
            Math.Max(singleRange.End, endExclusive));
    }

    private static bool MeasureRangeCoverageGap(Range range, ulong endExclusive, ref ulong cursor, ref ulong additional)
    {
        if (range.End <= cursor)
        {
            return true;
        }

        if (range.Start >= endExclusive)
        {
            return false;
        }

        if (range.Start > cursor)
        {
            additional += range.Start - cursor;
        }

        if (range.End >= endExclusive)
        {
            cursor = endExclusive;
            return false;
        }

        cursor = range.End;
        return true;
    }

    private static void AddTrailingGap(ulong endExclusive, ulong cursor, ref ulong additional)
    {
        if (cursor < endExclusive)
        {
            additional += endExclusive - cursor;
        }
    }

    /// <summary>
    /// Represents a stored half-open byte range.
    /// </summary>
    /// <param name="Start">The inclusive starting offset.</param>
    /// <param name="End">The exclusive ending offset.</param>
    private readonly record struct Range(ulong Start, ulong End);
}

internal readonly record struct QuicByteRange(ulong Start, ulong End);

internal readonly record struct QuicByteRangeSetSnapshot
{
    private readonly QuicByteRange singleRange;
    private readonly QuicByteRange[]? ranges;

    internal QuicByteRangeSetSnapshot(QuicByteRange[] ranges, ulong totalLength)
    {
        ArgumentNullException.ThrowIfNull(ranges);

        if (ranges.Length == 0)
        {
            this.ranges = null;
            singleRange = default;
            RangeCount = 0;
        }
        else if (ranges.Length == 1)
        {
            this.ranges = null;
            singleRange = ranges[0];
            RangeCount = 1;
        }
        else
        {
            this.ranges = ranges;
            singleRange = default;
            RangeCount = ranges.Length;
        }

        TotalLength = totalLength;
    }

    private QuicByteRangeSetSnapshot(int rangeCount, QuicByteRange singleRange, ulong totalLength)
    {
        ranges = null;
        this.singleRange = singleRange;
        RangeCount = rangeCount;
        TotalLength = totalLength;
    }

    internal int RangeCount { get; }

    internal ulong TotalLength { get; }

    internal QuicByteRange[] Ranges
    {
        get
        {
            return RangeCount switch
            {
                0 => [],
                1 => [singleRange],
                _ => ranges!,
            };
        }
    }

    internal static QuicByteRangeSetSnapshot CreateEmpty(ulong totalLength)
        => new(0, default, totalLength);

    internal static QuicByteRangeSetSnapshot CreateSingle(QuicByteRange range, ulong totalLength)
        => new(1, range, totalLength);

    internal QuicByteRange GetRange(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, RangeCount);
        return RangeCount == 1
            ? singleRange
            : ranges![index];
    }
}
