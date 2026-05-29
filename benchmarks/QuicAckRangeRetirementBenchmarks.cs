// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares sent-ACK-frame retirement collection with the previous lazy list against stack-backed packet numbers.
/// </summary>
[MemoryDiagnoser]
public class QuicAckRangeRetirementBenchmarks
{
    private const int StackAckFramePacketNumberCapacity = 32;

    private readonly Dictionary<ulong, int> sentAckFrames = [];
    private QuicAckFrame ackFrame = null!;

    /// <summary>
    /// Gets or sets the number of pending sent ACK-frame carrier packets.
    /// </summary>
    [Params(8, 32, 64)]
    public int PendingSentAckFrameCount { get; set; }

    /// <summary>
    /// Prepares a contiguous ACK range that acknowledges every pending sent ACK-frame carrier.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        sentAckFrames.Clear();
        for (ulong packetNumber = 1; packetNumber <= (ulong)PendingSentAckFrameCount; packetNumber++)
        {
            sentAckFrames.Add(packetNumber, unchecked((int)packetNumber));
        }

        ackFrame = new QuicAckFrame
        {
            LargestAcknowledged = (ulong)PendingSentAckFrameCount,
            FirstAckRange = (ulong)PendingSentAckFrameCount - 1,
        };
    }

    /// <summary>
    /// Baseline equivalent of the previous shape: lazy List&lt;ulong&gt; when a carrier packet is acknowledged.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int LazyListCollection()
    {
        List<ulong>? acknowledgedAckFramePacketNumbers = null;
        foreach (KeyValuePair<ulong, int> sentAckFrameEntry in sentAckFrames)
        {
            if (AckFrameAcknowledgesPacketNumber(ackFrame, sentAckFrameEntry.Key))
            {
                (acknowledgedAckFramePacketNumbers ??= []).Add(sentAckFrameEntry.Key);
            }
        }

        if (acknowledgedAckFramePacketNumbers is null)
        {
            return 0;
        }

        int checksum = 0;
        foreach (ulong packetNumber in acknowledgedAckFramePacketNumbers)
        {
            checksum ^= unchecked((int)packetNumber);
        }

        return checksum;
    }

    /// <summary>
    /// Measures stack-backed packet-number collection with pooled fallback for larger pending sets.
    /// </summary>
    [Benchmark]
    public int StackSpanCollection()
    {
        if (sentAckFrames.Count <= StackAckFramePacketNumberCapacity)
        {
            Span<ulong> acknowledgedAckFramePacketNumbers = stackalloc ulong[StackAckFramePacketNumberCapacity];
            return CollectWithSpan(acknowledgedAckFramePacketNumbers);
        }

        ulong[] rentedAcknowledgedPacketNumbers = ArrayPool<ulong>.Shared.Rent(sentAckFrames.Count);
        try
        {
            return CollectWithSpan(rentedAcknowledgedPacketNumbers.AsSpan(0, sentAckFrames.Count));
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(rentedAcknowledgedPacketNumbers);
        }
    }

    private int CollectWithSpan(Span<ulong> acknowledgedAckFramePacketNumbers)
    {
        int acknowledgedAckFramePacketNumberCount = 0;
        foreach (KeyValuePair<ulong, int> sentAckFrameEntry in sentAckFrames)
        {
            if (AckFrameAcknowledgesPacketNumber(ackFrame, sentAckFrameEntry.Key))
            {
                acknowledgedAckFramePacketNumbers[acknowledgedAckFramePacketNumberCount++] = sentAckFrameEntry.Key;
            }
        }

        int checksum = 0;
        for (int index = 0; index < acknowledgedAckFramePacketNumberCount; index++)
        {
            checksum ^= unchecked((int)acknowledgedAckFramePacketNumbers[index]);
        }

        return checksum;
    }

    private static bool AckFrameAcknowledgesPacketNumber(QuicAckFrame ackFrame, ulong packetNumber)
    {
        ulong firstRangeSmallestAcknowledged = ackFrame.LargestAcknowledged - ackFrame.FirstAckRange;
        if (packetNumber >= firstRangeSmallestAcknowledged && packetNumber <= ackFrame.LargestAcknowledged)
        {
            return true;
        }

        foreach (QuicAckRange range in ackFrame.AdditionalRangeSpan)
        {
            if (packetNumber >= range.SmallestAcknowledged && packetNumber <= range.LargestAcknowledged)
            {
                return true;
            }
        }

        return false;
    }
}
