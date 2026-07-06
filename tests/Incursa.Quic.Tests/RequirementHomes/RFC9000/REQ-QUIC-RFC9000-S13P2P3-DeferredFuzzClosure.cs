// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S13P2P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFramesRoundTripWithOneOrMoreAcknowledgedRanges()
    {
        foreach (QuicAckFrame frame in AckFrameCases())
        {
            byte[] encoded = QuicFrameTestData.BuildAckFrame(frame);

            Assert.True(QuicFrameCodec.TryParseAckFrame(encoded, out QuicAckFrame parsed, out int bytesConsumed));

            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.Equal(frame.FrameType, parsed.FrameType);
            Assert.Equal(frame.LargestAcknowledged, parsed.LargestAcknowledged);
            Assert.Equal(frame.AckDelay, parsed.AckDelay);
            Assert.Equal(frame.FirstAckRange, parsed.FirstAckRange);
            Assert.True(frame.FirstAckRange <= frame.LargestAcknowledged);
            Assert.Equal(frame.AdditionalRanges.Length, parsed.AdditionalRanges.Length);
            for (int index = 0; index < frame.AdditionalRanges.Length; index++)
            {
                Assert.Equal(frame.AdditionalRanges[index].Gap, parsed.AdditionalRanges[index].Gap);
                Assert.Equal(frame.AdditionalRanges[index].AckRangeLength, parsed.AdditionalRanges[index].AckRangeLength);
                Assert.Equal(frame.AdditionalRanges[index].SmallestAcknowledged, parsed.AdditionalRanges[index].SmallestAcknowledged);
                Assert.Equal(frame.AdditionalRanges[index].LargestAcknowledged, parsed.AdditionalRanges[index].LargestAcknowledged);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckRangeSelectionOmitsOldestRangesWhenRetainedRangeLimitIsExceeded()
    {
        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            QuicS13P2P3AckFrameProofSupport.CreateTrackedState(3, 1, 2, 5, 6, 9, 10),
            expectedLargestAcknowledged: 10,
            expectedFirstAckRange: 1,
            new QuicAckRange(1, 1, 5, 6),
            new QuicAckRange(1, 1, 1, 2));

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            QuicS13P2P3AckFrameProofSupport.CreateTrackedState(2, 1, 2, 5, 6, 9, 10),
            expectedLargestAcknowledged: 10,
            expectedFirstAckRange: 1,
            new QuicAckRange(1, 1, 5, 6));

        QuicS13P2P3AckFrameProofSupport.AssertBuildsAckFrame(
            QuicS13P2P3AckFrameProofSupport.CreateTrackedState(1, 1, 2, 5, 6, 9, 10),
            expectedLargestAcknowledged: 10,
            expectedFirstAckRange: 1);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P3-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFramesDoNotGuaranteeEveryProcessedPacketRemainsAcknowledged()
    {
        foreach (int maximumRetainedAckRanges in new[] { 1, 2 })
        {
            QuicAckGenerationState tracker = QuicS13P2P3AckFrameProofSupport.CreateTrackedState(
                maximumRetainedAckRanges,
                1,
                2,
                5,
                6,
                9,
                10);

            Assert.True(tracker.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 2_000,
                out QuicAckFrame frame));

            Assert.Equal(10UL, frame.LargestAcknowledged);
            Assert.Equal(1UL, frame.FirstAckRange);
            Assert.Equal(maximumRetainedAckRanges - 1, frame.AdditionalRanges.Length);
            Assert.DoesNotContain(frame.AdditionalRanges, range =>
                range.SmallestAcknowledged == 1 && range.LargestAcknowledged == 2);
        }
    }

    private static IEnumerable<QuicAckFrame> AckFrameCases()
    {
        yield return new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 5,
            AckDelay = 0,
            FirstAckRange = 0,
        };

        yield return new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 10,
            AckDelay = 300,
            FirstAckRange = 1,
            AdditionalRanges =
            [
                new QuicAckRange(1, 1, 5, 6),
            ],
        };

        yield return new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 10,
            AckDelay = 600,
            FirstAckRange = 1,
            AdditionalRanges =
            [
                new QuicAckRange(1, 1, 5, 6),
                new QuicAckRange(1, 1, 1, 2),
            ],
        };
    }
}
