// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicByteRangeSetTests
{
    [Fact]
    public void FreshSetHasNoCoverage()
    {
        QuicByteRangeSet ranges = new();

        Assert.Equal(10UL, ranges.MeasureAdditionalCoverage(0, 10));
        Assert.True(ranges.CoversPrefix(0));
        Assert.False(ranges.CoversPrefix(1));

        QuicByteRangeSetSnapshot snapshot = ranges.CaptureSnapshot();
        Assert.Empty(snapshot.Ranges);
        Assert.Equal(0UL, snapshot.TotalLength);
    }

    [Fact]
    public void AddFirstRangeTracksSingleCoverage()
    {
        QuicByteRangeSet ranges = new();

        Assert.Equal(10UL, ranges.Add(0, 10));

        Assert.Equal(10UL, ranges.TotalLength);
        Assert.True(ranges.CoversPrefix(10));
        Assert.Equal(0UL, ranges.MeasureAdditionalCoverage(3, 7));

        AssertRanges(ranges.CaptureSnapshot(), (0, 10));
    }

    [Fact]
    public void AddTouchingRangeMergesSingleRange()
    {
        QuicByteRangeSet ranges = new();

        Assert.Equal(10UL, ranges.Add(0, 10));
        Assert.Equal(10UL, ranges.Add(10, 20));

        Assert.Equal(20UL, ranges.TotalLength);
        Assert.True(ranges.CoversPrefix(20));
        AssertRanges(ranges.CaptureSnapshot(), (0, 20));
    }

    [Fact]
    public void AddDisjointRangesPreservesOrderAndCoverage()
    {
        QuicByteRangeSet ranges = new();

        Assert.Equal(10UL, ranges.Add(20, 30));
        Assert.Equal(10UL, ranges.Add(0, 10));

        Assert.Equal(20UL, ranges.TotalLength);
        Assert.False(ranges.CoversPrefix(30));
        Assert.Equal(10UL, ranges.MeasureAdditionalCoverage(5, 25));
        AssertRanges(ranges.CaptureSnapshot(), (0, 10), (20, 30));
    }

    [Fact]
    public void AddBridgingRangeMergesMultipleRanges()
    {
        QuicByteRangeSet ranges = new();

        Assert.Equal(10UL, ranges.Add(0, 10));
        Assert.Equal(10UL, ranges.Add(20, 30));
        Assert.Equal(10UL, ranges.Add(10, 20));

        Assert.Equal(30UL, ranges.TotalLength);
        Assert.True(ranges.CoversPrefix(30));
        AssertRanges(ranges.CaptureSnapshot(), (0, 30));
    }

    [Fact]
    public void RestoreRoundTripsSingleAndMultipleRanges()
    {
        QuicByteRangeSet singleSource = new();
        singleSource.Add(5, 15);

        QuicByteRangeSet restoredSingle = new();
        restoredSingle.Restore(singleSource.CaptureSnapshot());

        Assert.Equal(10UL, restoredSingle.TotalLength);
        AssertRanges(restoredSingle.CaptureSnapshot(), (5, 15));

        QuicByteRangeSet multiSource = new();
        multiSource.Add(20, 30);
        multiSource.Add(0, 10);

        QuicByteRangeSet restoredMulti = new();
        restoredMulti.Restore(multiSource.CaptureSnapshot());

        Assert.Equal(20UL, restoredMulti.TotalLength);
        AssertRanges(restoredMulti.CaptureSnapshot(), (0, 10), (20, 30));
    }

    private static void AssertRanges(QuicByteRangeSetSnapshot snapshot, params (ulong Start, ulong End)[] expected)
    {
        Assert.Equal(expected.Length, snapshot.Ranges.Length);
        for (int index = 0; index < expected.Length; index++)
        {
            Assert.Equal(expected[index].Start, snapshot.Ranges[index].Start);
            Assert.Equal(expected[index].End, snapshot.Ranges[index].End);
        }
    }
}
