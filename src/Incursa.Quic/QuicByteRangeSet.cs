namespace Incursa.Quic;

internal sealed class QuicByteRangeSet
{
    private readonly List<Range> ranges = [];

    public ulong TotalLength { get; private set; }

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

    private readonly record struct Range(ulong Start, ulong End);
}
