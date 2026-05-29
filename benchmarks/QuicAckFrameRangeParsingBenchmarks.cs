// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares ACK range parsing with an allocating range array against the pooled parser.
/// </summary>
[MemoryDiagnoser]
public class QuicAckFrameRangeParsingBenchmarks
{
    private const byte AckFrameType = 0x02;
    private const ulong AckRangeGapAdjustment = 1;

    private byte[] ackPayload = [];

    /// <summary>
    /// Gets or sets the number of additional ACK ranges encoded in the benchmark payload.
    /// </summary>
    [Params(3, 20)]
    public int AdditionalRangeCount { get; set; }

    /// <summary>
    /// Prepares a valid ACK payload with the configured number of additional ranges.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        List<byte> payload =
        [
            AckFrameType,
            0x67,
            0x13,
            0x10,
            (byte)AdditionalRangeCount,
            0x03,
        ];

        for (int index = 0; index < AdditionalRangeCount; index++)
        {
            payload.Add(0x01);
            payload.Add(0x00);
        }

        ackPayload = payload.ToArray();
    }

    /// <summary>
    /// Baseline equivalent of the previous parser shape: exact range array per parsed ACK frame.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int ParseWithAllocatedRangeArray()
    {
        return TryParseAckFrameWithAllocatedRangeArray(ackPayload, out QuicAckFrame frame, out int bytesConsumed)
            ? ConsumeParsedFrame(frame, bytesConsumed)
            : -1;
    }

    /// <summary>
    /// Measures the production parser that owns a pooled range buffer until the frame is disposed.
    /// </summary>
    [Benchmark]
    public int ParseWithPooledRangeArray()
    {
        if (!QuicFrameCodec.TryParseAckFrame(ackPayload, out QuicAckFrame frame, out int bytesConsumed))
        {
            return -1;
        }

        try
        {
            return ConsumeParsedFrame(frame, bytesConsumed);
        }
        finally
        {
            frame.Dispose();
        }
    }

    private static int ConsumeParsedFrame(QuicAckFrame frame, int bytesConsumed)
    {
        ReadOnlySpan<QuicAckRange> additionalRanges = frame.AdditionalRangeSpan;
        return bytesConsumed
            ^ unchecked((int)frame.LargestAcknowledged)
            ^ unchecked((int)frame.AckDelay)
            ^ frame.AdditionalRangeSpan.Length
            ^ unchecked((int)additionalRanges[0].LargestAcknowledged);
    }

    private static bool TryParseAckFrameWithAllocatedRangeArray(
        ReadOnlySpan<byte> packetPayload,
        out QuicAckFrame frame,
        out int bytesConsumed)
    {
        frame = null!;
        bytesConsumed = default;

        if (!QuicVariableLengthInteger.TryParse(packetPayload, out ulong frameTypeValue, out int index)
            || index != 1
            || frameTypeValue != AckFrameType
            || !TryParseVarint(packetPayload, ref index, out ulong largestAcknowledged)
            || !TryParseVarint(packetPayload, ref index, out ulong ackDelay)
            || !TryParseVarint(packetPayload, ref index, out ulong ackRangeCount)
            || !TryParseVarint(packetPayload, ref index, out ulong firstAckRange)
            || firstAckRange > largestAcknowledged
            || ackRangeCount > int.MaxValue)
        {
            return false;
        }

        ulong maximumCompleteRangesInPayload = (ulong)(packetPayload.Length - index) / 2;
        if (ackRangeCount > maximumCompleteRangesInPayload)
        {
            return false;
        }

        QuicAckRange[] additionalRanges = ackRangeCount == 0
            ? []
            : new QuicAckRange[(int)ackRangeCount];
        ulong previousSmallestAcknowledged = largestAcknowledged - firstAckRange;
        for (int rangeIndex = 0; rangeIndex < additionalRanges.Length; rangeIndex++)
        {
            if (!TryParseVarint(packetPayload, ref index, out ulong gap)
                || !TryParseVarint(packetPayload, ref index, out ulong ackRangeLength)
                || !TryComputeAckRange(
                    previousSmallestAcknowledged,
                    gap,
                    ackRangeLength,
                    out ulong smallestAcknowledged,
                    out ulong largestRangeAcknowledged))
            {
                return false;
            }

            additionalRanges[rangeIndex] = new QuicAckRange(gap, ackRangeLength, smallestAcknowledged, largestRangeAcknowledged);
            previousSmallestAcknowledged = smallestAcknowledged;
        }

        frame = new QuicAckFrame
        {
            FrameType = AckFrameType,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = ackDelay,
            FirstAckRange = firstAckRange,
            AdditionalRanges = additionalRanges,
        };
        bytesConsumed = index;
        return true;
    }

    private static bool TryParseVarint(ReadOnlySpan<byte> packetPayload, ref int index, out ulong value)
    {
        value = default;
        if (index >= packetPayload.Length
            || !QuicVariableLengthInteger.TryParse(packetPayload[index..], out value, out int bytesConsumed))
        {
            return false;
        }

        index += bytesConsumed;
        return true;
    }

    private static bool TryComputeAckRange(
        ulong previousSmallestAcknowledged,
        ulong gap,
        ulong ackRangeLength,
        out ulong smallestAcknowledged,
        out ulong largestAcknowledged)
    {
        smallestAcknowledged = default;
        largestAcknowledged = default;

        if (previousSmallestAcknowledged < gap + AckRangeGapAdjustment)
        {
            return false;
        }

        largestAcknowledged = previousSmallestAcknowledged - gap - AckRangeGapAdjustment;
        if (largestAcknowledged < ackRangeLength)
        {
            return false;
        }

        smallestAcknowledged = largestAcknowledged - ackRangeLength;
        return true;
    }
}
