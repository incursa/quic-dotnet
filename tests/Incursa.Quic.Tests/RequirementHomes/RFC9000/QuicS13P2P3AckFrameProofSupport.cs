// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS13P2P3AckFrameProofSupport
{
    public static QuicAckGenerationState CreateTrackedState(int maximumRetainedAckRanges)
    {
        return CreateTrackedState(maximumRetainedAckRanges, 1, 2, 5, 6, 9, 10);
    }

    public static QuicAckGenerationState CreateTrackedState(int maximumRetainedAckRanges, params ulong[] packetNumbers)
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges);
        ulong receivedAtMicros = 1_000;

        foreach (ulong packetNumber in packetNumbers)
        {
            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: receivedAtMicros);
            receivedAtMicros += 10;
        }

        return tracker;
    }

    public static void AssertBuildsAckFrame(
        QuicAckGenerationState tracker,
        ulong expectedLargestAcknowledged,
        ulong expectedFirstAckRange,
        params QuicAckRange[] expectedAdditionalRanges)
    {
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(0x02, frame.FrameType);
        Assert.Equal(expectedLargestAcknowledged, frame.LargestAcknowledged);
        Assert.Equal(expectedFirstAckRange, frame.FirstAckRange);
        Assert.Equal(expectedAdditionalRanges.Length, frame.AdditionalRanges.Length);

        for (int index = 0; index < expectedAdditionalRanges.Length; index++)
        {
            Assert.Equal(expectedAdditionalRanges[index].Gap, frame.AdditionalRanges[index].Gap);
            Assert.Equal(expectedAdditionalRanges[index].AckRangeLength, frame.AdditionalRanges[index].AckRangeLength);
            Assert.Equal(expectedAdditionalRanges[index].SmallestAcknowledged, frame.AdditionalRanges[index].SmallestAcknowledged);
            Assert.Equal(expectedAdditionalRanges[index].LargestAcknowledged, frame.AdditionalRanges[index].LargestAcknowledged);
        }
    }

    public static void AssertBuildsThreeRangeAckFrame(QuicAckGenerationState tracker)
    {
        AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 10,
            expectedFirstAckRange: 1,
            new QuicAckRange(1, 1, 5, 6),
            new QuicAckRange(1, 1, 1, 2));
    }

    public static void AssertBuildsTrimmedAckFrame(QuicAckGenerationState tracker)
    {
        AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 10,
            expectedFirstAckRange: 1,
            new QuicAckRange(1, 1, 5, 6));
    }

    public static void AssertBuildsSingleRangeAckFrame(QuicAckGenerationState tracker)
    {
        AssertBuildsAckFrame(
            tracker,
            expectedLargestAcknowledged: 10,
            expectedFirstAckRange: 1);
    }
}
