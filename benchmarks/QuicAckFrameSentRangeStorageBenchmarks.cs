// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the ACK-range retention shape used for sent ACK frames before and after pooling.
/// </summary>
[MemoryDiagnoser]
public class QuicAckFrameSentRangeStorageBenchmarks
{
    private QuicAckFrame ackFrame = null!;

    /// <summary>
    /// Gets or sets the number of additional ACK ranges to retain for a sent ACK frame.
    /// </summary>
    [Params(0, 3, 20)]
    public int AdditionalRangeCount { get; set; }

    /// <summary>
    /// Prepares a representative ACK frame with the requested number of additional ranges.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        ackFrame = new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 1_000,
            AckDelay = 16,
            FirstAckRange = 0,
            AdditionalRanges = BuildAdditionalRanges(AdditionalRangeCount),
        };
    }

    /// <summary>
    /// Baseline equivalent of the previous shape: allocate a fresh PacketRange[] for every sent ACK frame.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int AllocateSentAckRanges()
    {
        PacketRange[] ackedRanges = BuildAckFrameRangesWithAllocatedArray(ackFrame);
        return ConsumeAckedRanges(ackedRanges, ackedRanges.Length);
    }

    /// <summary>
    /// Measures the pooled storage shape used by the production ACK-frame retirement bookkeeping.
    /// </summary>
    [Benchmark]
    public int PoolSentAckRanges()
    {
        PacketRange[] ackedRanges = BuildAckFrameRangesWithPooledArray(ackFrame, out int ackedRangeCount);
        try
        {
            return ConsumeAckedRanges(ackedRanges, ackedRangeCount);
        }
        finally
        {
            ArrayPool<PacketRange>.Shared.Return(ackedRanges);
        }
    }

    private static QuicAckRange[] BuildAdditionalRanges(int additionalRangeCount)
    {
        if (additionalRangeCount == 0)
        {
            return [];
        }

        QuicAckRange[] ranges = new QuicAckRange[additionalRangeCount];
        ulong previousSmallestAcknowledged = 1_000;
        for (int index = 0; index < additionalRangeCount; index++)
        {
            ulong gap = 1;
            ulong ackRangeLength = 0;
            ulong largestAcknowledged = previousSmallestAcknowledged - gap - 1;
            ulong smallestAcknowledged = largestAcknowledged - ackRangeLength;
            ranges[index] = new QuicAckRange(gap, ackRangeLength, smallestAcknowledged, largestAcknowledged);
            previousSmallestAcknowledged = smallestAcknowledged;
        }

        return ranges;
    }

    private static PacketRange[] BuildAckFrameRangesWithAllocatedArray(QuicAckFrame frame)
    {
        PacketRange[] ranges = new PacketRange[1 + frame.AdditionalRangeCount];
        ranges[0] = new PacketRange(frame.LargestAcknowledged - frame.FirstAckRange, frame.LargestAcknowledged);
        int rangeIndex = 1;
        foreach (QuicAckRange additionalRange in frame.AdditionalRangeSpan)
        {
            ranges[rangeIndex++] = new PacketRange(additionalRange.SmallestAcknowledged, additionalRange.LargestAcknowledged);
        }

        return ranges;
    }

    private static PacketRange[] BuildAckFrameRangesWithPooledArray(QuicAckFrame frame, out int rangeCount)
    {
        rangeCount = checked(1 + frame.AdditionalRangeCount);
        PacketRange[] ranges = ArrayPool<PacketRange>.Shared.Rent(rangeCount);
        ranges[0] = new PacketRange(frame.LargestAcknowledged - frame.FirstAckRange, frame.LargestAcknowledged);
        int rangeIndex = 1;
        foreach (QuicAckRange additionalRange in frame.AdditionalRangeSpan)
        {
            ranges[rangeIndex++] = new PacketRange(additionalRange.SmallestAcknowledged, additionalRange.LargestAcknowledged);
        }

        return ranges;
    }

    private static int ConsumeAckedRanges(PacketRange[] ackedRanges, int ackedRangeCount)
    {
        int checksum = ackedRangeCount;
        for (int index = 0; index < ackedRangeCount; index++)
        {
            checksum ^= unchecked((int)ackedRanges[index].Smallest);
        }

        return checksum;
    }

    private readonly record struct PacketRange(ulong Smallest, ulong Largest);
}
