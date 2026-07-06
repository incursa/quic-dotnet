// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P4-0001">In cases with ACK frame loss and reordering, this approach does not guarantee that every acknowledgment is seen by the sender before it is no longer included in the ACK frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
public sealed class REQ_QUIC_RFC9000_S13P2P4_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_PreservesTheTrackedAckRangesBeforeNewerPacketsArrive()
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges: 2);
        RecordAckedRanges(tracker);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(6UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(1UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(2UL, frame.AdditionalRanges[0].LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0003")]
    [Requirement("RFC9000-S13-2-3-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildAckFrame_DropsTheOldestAckRangeAfterTheWindowAdvances()
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges: 2);
        RecordAckedRanges(tracker);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            9,
            ackEliciting: true,
            receivedAtMicros: 1_060);
        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            10,
            ackEliciting: true,
            receivedAtMicros: 1_070);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(10UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Single(frame.AdditionalRanges);
        Assert.Equal(1UL, frame.AdditionalRanges[0].Gap);
        Assert.Equal(1UL, frame.AdditionalRanges[0].AckRangeLength);
        Assert.Equal(5UL, frame.AdditionalRanges[0].SmallestAcknowledged);
        Assert.Equal(6UL, frame.AdditionalRanges[0].LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
    [Requirement("REQ-QUIC-RFC9000-13233")]
    [Requirement("REQ-QUIC-RFC9000-13235")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-13236")]
    [Requirement("RFC9000-S13-2-3-P6-S1-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_WithASingleRangeLimitKeepsOnlyTheNewestAckRange()
    {
        QuicAckGenerationState tracker = new(maximumRetainedAckRanges: 1);
        RecordAckedRanges(tracker);

        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 2_000,
            out QuicAckFrame frame));

        Assert.Equal(6UL, frame.LargestAcknowledged);
        Assert.Equal(1UL, frame.FirstAckRange);
        Assert.Empty(frame.AdditionalRanges);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P4-0001")]
    [Requirement("REQ-QUIC-RFC9000-13233")]
    [Requirement("REQ-QUIC-RFC9000-13235")]
    [Requirement("REQ-QUIC-RFC9000-13236")]
    [Requirement("RFC9000-S13-2-3-P6-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckRangeRetentionLimitsKeepNewestRangesAndLargestProcessedPacket()
    {
        AckRetentionFuzzCase[] scenarios =
        [
            new(MaximumRetainedAckRanges: 1, PacketNumbers: [1, 2, 5, 6, 9, 10]),
            new(MaximumRetainedAckRanges: 2, PacketNumbers: [1, 2, 5, 6, 9, 10]),
            new(MaximumRetainedAckRanges: 3, PacketNumbers: [1, 2, 5, 6, 9, 10]),
            new(MaximumRetainedAckRanges: 2, PacketNumbers: [0, 3, 4, 8, 9, 10, 14]),
            new(MaximumRetainedAckRanges: 4, PacketNumbers: [2, 4, 6, 8, 10, 12, 14]),
            new(MaximumRetainedAckRanges: 2, PacketNumbers: [20, 21, 24, 30, 31, 40]),
        ];

        foreach (AckRetentionFuzzCase scenario in scenarios)
        {
            QuicAckGenerationState tracker = CreateTrackedState(scenario);

            Assert.True(tracker.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 5_000,
                out QuicAckFrame frame));

            PacketRange[] expectedRanges = BuildExpectedRetainedRanges(
                scenario.PacketNumbers,
                scenario.MaximumRetainedAckRanges);

            Assert.NotEmpty(expectedRanges);
            PacketRange newestRange = expectedRanges[^1];
            Assert.Equal(newestRange.Largest, frame.LargestAcknowledged);
            Assert.Equal(newestRange.Largest - newestRange.Smallest, frame.FirstAckRange);
            Assert.True(1 + frame.AdditionalRanges.Length <= scenario.MaximumRetainedAckRanges);
            Assert.Equal(Math.Max(0, expectedRanges.Length - 1), frame.AdditionalRanges.Length);

            ulong previousSmallestAcknowledged = newestRange.Smallest;
            for (int rangeIndex = expectedRanges.Length - 2, additionalIndex = 0;
                rangeIndex >= 0;
                rangeIndex--, additionalIndex++)
            {
                PacketRange expectedRange = expectedRanges[rangeIndex];
                QuicAckRange actualRange = frame.AdditionalRanges[additionalIndex];
                Assert.Equal(previousSmallestAcknowledged - expectedRange.Largest - 2, actualRange.Gap);
                Assert.Equal(expectedRange.Largest - expectedRange.Smallest, actualRange.AckRangeLength);
                Assert.Equal(expectedRange.Smallest, actualRange.SmallestAcknowledged);
                Assert.Equal(expectedRange.Largest, actualRange.LargestAcknowledged);
                previousSmallestAcknowledged = expectedRange.Smallest;
            }
        }
    }

    [Fact]
    [Requirement("RFC9000-S13-2-3-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckRangesRemainUntilTheirCarrierPacketIsAcknowledgedInTheSamePacketNumberSpace()
    {
        AckRetentionFuzzCase[] scenarios =
        [
            new(MaximumRetainedAckRanges: 2, PacketNumbers: [1, 2, 5, 6, 9, 10]),
            new(MaximumRetainedAckRanges: 3, PacketNumbers: [3, 4, 8, 9, 12]),
            new(MaximumRetainedAckRanges: 4, PacketNumbers: [2, 4, 6, 8, 10, 12, 14]),
        ];

        for (int scenarioIndex = 0; scenarioIndex < scenarios.Length; scenarioIndex++)
        {
            AckRetentionFuzzCase scenario = scenarios[scenarioIndex];
            QuicAckGenerationState tracker = CreateTrackedState(scenario);

            Assert.True(tracker.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 5_000,
                out QuicAckFrame frame));

            ulong carrierPacketNumber = (ulong)(100 + scenarioIndex);
            tracker.MarkAckFrameSent(
                QuicPacketNumberSpace.ApplicationData,
                carrierPacketNumber,
                frame,
                sentAtMicros: 5_100,
                ackOnlyPacket: true);

            Assert.False(tracker.TryRetireAcknowledgedAckRanges(
                QuicPacketNumberSpace.Initial,
                carrierPacketNumber));
            Assert.True(tracker.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 5_200,
                out QuicAckFrame stillRetainedFrame));
            AssertAckFramesEqual(frame, stillRetainedFrame);

            Assert.True(tracker.TryRetireAcknowledgedAckRanges(
                QuicPacketNumberSpace.ApplicationData,
                carrierPacketNumber));
            Assert.False(tracker.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 5_300,
                out _));
        }
    }

    private static void RecordAckedRanges(QuicAckGenerationState tracker)
    {
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 1, ackEliciting: true, receivedAtMicros: 1_000);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 2, ackEliciting: true, receivedAtMicros: 1_010);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 5, ackEliciting: true, receivedAtMicros: 1_020);
        tracker.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, 6, ackEliciting: true, receivedAtMicros: 1_030);
    }

    private static QuicAckGenerationState CreateTrackedState(AckRetentionFuzzCase scenario)
    {
        QuicAckGenerationState tracker = new(scenario.MaximumRetainedAckRanges);
        for (int index = 0; index < scenario.PacketNumbers.Length; index++)
        {
            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                scenario.PacketNumbers[index],
                ackEliciting: true,
                receivedAtMicros: (ulong)(1_000 + (index * 10)));
        }

        return tracker;
    }

    private static PacketRange[] BuildExpectedRetainedRanges(ReadOnlySpan<ulong> packetNumbers, int maximumRetainedAckRanges)
    {
        List<PacketRange> ranges = [];
        ulong rangeSmallest = packetNumbers[0];
        ulong rangeLargest = packetNumbers[0];

        for (int index = 1; index < packetNumbers.Length; index++)
        {
            ulong packetNumber = packetNumbers[index];
            if (packetNumber == rangeLargest + 1)
            {
                rangeLargest = packetNumber;
                continue;
            }

            ranges.Add(new PacketRange(rangeSmallest, rangeLargest));
            rangeSmallest = packetNumber;
            rangeLargest = packetNumber;
        }

        ranges.Add(new PacketRange(rangeSmallest, rangeLargest));

        int firstRetainedRangeIndex = Math.Max(0, ranges.Count - maximumRetainedAckRanges);
        return ranges.Skip(firstRetainedRangeIndex).ToArray();
    }

    private static void AssertAckFramesEqual(QuicAckFrame expected, QuicAckFrame actual)
    {
        Assert.Equal(expected.LargestAcknowledged, actual.LargestAcknowledged);
        Assert.Equal(expected.FirstAckRange, actual.FirstAckRange);
        Assert.Equal(expected.AdditionalRanges.Length, actual.AdditionalRanges.Length);
        for (int index = 0; index < expected.AdditionalRanges.Length; index++)
        {
            Assert.Equal(expected.AdditionalRanges[index].Gap, actual.AdditionalRanges[index].Gap);
            Assert.Equal(expected.AdditionalRanges[index].AckRangeLength, actual.AdditionalRanges[index].AckRangeLength);
            Assert.Equal(expected.AdditionalRanges[index].SmallestAcknowledged, actual.AdditionalRanges[index].SmallestAcknowledged);
            Assert.Equal(expected.AdditionalRanges[index].LargestAcknowledged, actual.AdditionalRanges[index].LargestAcknowledged);
        }
    }

    private readonly record struct AckRetentionFuzzCase(int MaximumRetainedAckRanges, ulong[] PacketNumbers);

    private readonly record struct PacketRange(ulong Smallest, ulong Largest);
}
