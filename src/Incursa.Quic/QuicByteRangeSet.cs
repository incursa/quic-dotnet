namespace Incursa.Quic;

/// <summary>
/// Maintains a normalized, non-overlapping set of half-open byte ranges and tracks the total
/// amount of unique coverage across all stored ranges.
/// </summary>
internal sealed class QuicByteRangeSet
{
    // Stored ranges are coalesced so each byte offset appears at most once.
    private readonly List<Range> ranges = [];

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

        ulong additional = 0;
        ulong cursor = start;

        foreach (Range range in ranges)
        {
            if (range.End <= cursor)
            {
                continue;
            }

            if (range.Start >= endExclusive)
            {
                break;
            }

            if (range.Start > cursor)
            {
                additional += range.Start - cursor;
            }

            if (range.End >= endExclusive)
            {
                cursor = endExclusive;
                break;
            }

            cursor = range.End;
        }

        if (cursor < endExclusive)
        {
            additional += endExclusive - cursor;
        }

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

        return ranges.Count > 0
            && ranges[0].Start == 0
            && ranges[0].End >= endExclusive;
    }

    /// <summary>
    /// Represents a stored half-open byte range.
    /// </summary>
    /// <param name="Start">The inclusive starting offset.</param>
    /// <param name="End">The exclusive ending offset.</param>
    private readonly record struct Range(ulong Start, ulong End);
}
