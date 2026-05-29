// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares ACK-frame construction with the previous list-based range builder against the production span-based builder.
/// </summary>
[MemoryDiagnoser]
public class QuicAckGenerationStateBuildBenchmarks
{
    private const byte AckFrameType = 0x02;

    private readonly List<ulong> packetNumbers = [];
    private readonly Dictionary<ulong, ulong> receivedAtMicrosByPacketNumber = [];

    /// <summary>
    /// Gets or sets the number of disjoint one-packet ACK ranges to build.
    /// </summary>
    [Params(8, 32)]
    public int AckRangeCount { get; set; }

    /// <summary>
    /// Initializes a sorted packet-number set that forces the requested number of ACK ranges.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        packetNumbers.Clear();
        receivedAtMicrosByPacketNumber.Clear();
        for (int index = 0; index < AckRangeCount; index++)
        {
            ulong packetNumber = (ulong)((index * 2) + 1);
            packetNumbers.Add(packetNumber);
            receivedAtMicrosByPacketNumber.Add(packetNumber, packetNumber);
        }
    }

    /// <summary>
    /// Baseline equivalent of the previous ACK builder shape: list-backed ranges plus ToArray for frame ranges.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int ListBasedAckFrameConstruction()
    {
        List<PacketRange> ranges = BuildRangesList(packetNumbers);
        if (ranges.Count == 0)
        {
            return -1;
        }

        PacketRange newestRange = ranges[^1];
        List<QuicAckRange> additionalRanges = [];
        ulong previousSmallestAcknowledged = newestRange.Smallest;

        for (int rangeIndex = ranges.Count - 2; rangeIndex >= 0; rangeIndex--)
        {
            PacketRange range = ranges[rangeIndex];
            ulong gap = previousSmallestAcknowledged - range.Largest - 2;
            ulong ackRangeLength = range.Largest - range.Smallest;
            additionalRanges.Add(new QuicAckRange(gap, ackRangeLength, range.Smallest, range.Largest));
            previousSmallestAcknowledged = range.Smallest;
        }

        QuicAckFrame frame = new()
        {
            FrameType = AckFrameType,
            LargestAcknowledged = newestRange.Largest,
            AckDelay = GetAckDelayMicros(nowMicros: 100, receivedAtMicrosByPacketNumber[newestRange.Largest]),
            FirstAckRange = newestRange.Largest - newestRange.Smallest,
            AdditionalRanges = additionalRanges.ToArray(),
        };

        return ConsumeFrame(frame);
    }

    /// <summary>
    /// Measures the production ACK builder after replacing transient range lists with stack-backed spans.
    /// </summary>
    [Benchmark]
    public int SpanBasedAckFrameConstruction()
    {
        Span<PacketRange> ranges = stackalloc PacketRange[32];
        int rangeCount = BuildRangesSpan(packetNumbers, ranges);
        if (rangeCount == 0)
        {
            return -1;
        }

        PacketRange newestRange = ranges[rangeCount - 1];
        int additionalRangeCount = rangeCount - 1;
        QuicAckRange[] additionalRanges = additionalRangeCount == 0
            ? []
            : new QuicAckRange[additionalRangeCount];
        ulong previousSmallestAcknowledged = newestRange.Smallest;

        for (int rangeIndex = rangeCount - 2, additionalRangeIndex = 0;
            rangeIndex >= 0;
            rangeIndex--, additionalRangeIndex++)
        {
            PacketRange range = ranges[rangeIndex];
            ulong gap = previousSmallestAcknowledged - range.Largest - 2;
            ulong ackRangeLength = range.Largest - range.Smallest;
            additionalRanges[additionalRangeIndex] = new QuicAckRange(gap, ackRangeLength, range.Smallest, range.Largest);
            previousSmallestAcknowledged = range.Smallest;
        }

        QuicAckFrame frame = new()
        {
            FrameType = AckFrameType,
            LargestAcknowledged = newestRange.Largest,
            AckDelay = GetAckDelayMicros(nowMicros: 100, receivedAtMicrosByPacketNumber[newestRange.Largest]),
            FirstAckRange = newestRange.Largest - newestRange.Smallest,
            AdditionalRanges = additionalRanges,
        };

        return ConsumeFrame(frame);
    }

    private static List<PacketRange> BuildRangesList(IEnumerable<ulong> packetNumbers)
    {
        List<PacketRange> ranges = [];

        using IEnumerator<ulong> enumerator = packetNumbers.GetEnumerator();
        if (!enumerator.MoveNext())
        {
            return ranges;
        }

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

            ranges.Add(new PacketRange(rangeStart, rangeEnd));
            rangeStart = packetNumber;
            rangeEnd = packetNumber;
        }

        ranges.Add(new PacketRange(rangeStart, rangeEnd));
        return ranges;
    }

    private static int BuildRangesSpan(IEnumerable<ulong> packetNumbers, Span<PacketRange> ranges)
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

    private static int ConsumeFrame(QuicAckFrame frame)
    {
        int checksum = unchecked((int)frame.LargestAcknowledged)
            ^ unchecked((int)frame.FirstAckRange)
            ^ frame.AdditionalRangeCount;
        foreach (QuicAckRange range in frame.AdditionalRangeSpan)
        {
            checksum ^= unchecked((int)range.SmallestAcknowledged);
        }

        return checksum;
    }

    private static ulong GetAckDelayMicros(ulong nowMicros, ulong receivedAtMicros)
    {
        return nowMicros > receivedAtMicros ? nowMicros - receivedAtMicros : 0;
    }

    private readonly record struct PacketRange(ulong Smallest, ulong Largest);
}
