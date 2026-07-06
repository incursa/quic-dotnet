// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S6_1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S6-1-1-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketThresholdUsesTheRecommendedThreePacketFloor()
    {
        Assert.Equal(3, QuicRecoveryTiming.RecommendedPacketThreshold);

        foreach ((ulong packetNumber, ulong largestAcknowledgedPacketNumber, bool expectedLost) in new[]
        {
            (0UL, 0UL, false),
            (0UL, 2UL, false),
            (0UL, 3UL, true),
            (1UL, 3UL, false),
            (7UL, 10UL, true),
            (8UL, 10UL, false),
            (1_000UL, 1_003UL, true),
            (1_001UL, 1_003UL, false),
        })
        {
            Assert.Equal(expectedLost, QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                packetNumber,
                largestAcknowledgedPacketNumber));
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-1-1-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketThresholdRejectsValuesBelowThreeAndHonorsHigherValues()
    {
        foreach (int packetThreshold in new[] { int.MinValue, -1, 0, 1, 2 })
        {
            ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
                QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                    packetNumber: 0,
                    largestAcknowledgedPacketNumber: 3,
                    packetThreshold: packetThreshold));

            Assert.Equal("packetThreshold", exception.ParamName);
        }

        foreach ((ulong packetNumber, ulong largestAcknowledgedPacketNumber, int packetThreshold, bool expectedLost) in new[]
        {
            (0UL, 3UL, 3, true),
            (0UL, 3UL, 4, false),
            (6UL, 10UL, 4, true),
            (7UL, 10UL, 4, false),
            (10UL, 20UL, 10, true),
            (11UL, 20UL, 10, false),
        })
        {
            Assert.Equal(expectedLost, QuicRecoveryTiming.ShouldDeclarePacketLostByPacketThreshold(
                packetNumber,
                largestAcknowledgedPacketNumber,
                packetThreshold));
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-1-2-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RemainingLossDelayReachesZeroAtAndAfterTheTimeThreshold()
    {
        foreach ((ulong packetSentAtMicros, ulong nowMicros, ulong latestRttMicros, ulong smoothedRttMicros, ulong expectedRemainingMicros) in new[]
        {
            (1_000UL, 2_124UL, 800UL, 1_000UL, 1UL),
            (1_000UL, 2_125UL, 800UL, 1_000UL, 0UL),
            (1_000UL, 2_500UL, 800UL, 1_000UL, 0UL),
            (5_000UL, 5_999UL, 0UL, 0UL, 1UL),
            (5_000UL, 6_000UL, 0UL, 0UL, 0UL),
            (10_000UL, 11_349UL, 1_200UL, 1_000UL, 1UL),
            (10_000UL, 11_350UL, 1_200UL, 1_000UL, 0UL),
        })
        {
            Assert.True(QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
                packetSentAtMicros,
                nowMicros,
                latestRttMicros,
                smoothedRttMicros,
                out ulong remainingLossDelayMicros));

            Assert.Equal(expectedRemainingMicros, remainingLossDelayMicros);
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-1-2-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LossDelayThresholdIsNeverBelowLocalTimerGranularity()
    {
        foreach ((ulong latestRttMicros, ulong smoothedRttMicros, ulong timerGranularityMicros, ulong expectedLossDelayMicros) in new[]
        {
            (0UL, 0UL, 1UL, 1UL),
            (0UL, 0UL, 1_000UL, 1_000UL),
            (1UL, 1UL, 1_000UL, 1_000UL),
            (800UL, 800UL, 1_000UL, 1_000UL),
            (889UL, 889UL, 1_000UL, 1_000UL),
            (900UL, 900UL, 1_000UL, 1_012UL),
            (1_200UL, 1_000UL, 1_000UL, 1_350UL),
            (1_000UL, 1_200UL, 1_000UL, 1_350UL),
        })
        {
            ulong lossDelayMicros = QuicRecoveryTiming.ComputeLossDelayMicros(
                latestRttMicros,
                smoothedRttMicros,
                timerGranularityMicros: timerGranularityMicros);

            Assert.Equal(expectedLossDelayMicros, lossDelayMicros);
            Assert.True(lossDelayMicros >= timerGranularityMicros);
        }
    }
}
