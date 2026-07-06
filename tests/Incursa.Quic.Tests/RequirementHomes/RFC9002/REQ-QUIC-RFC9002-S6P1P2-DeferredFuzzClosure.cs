// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S6P1P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0006")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ComputeLossDelayMicros_AppliesThresholdMultiplierAndGranularity()
    {
        Assert.Equal(1_000UL, QuicRecoveryTiming.RecommendedTimerGranularityMicros);

        foreach ((ulong latestRttMicros, ulong smoothedRttMicros, ulong numerator, ulong denominator, ulong granularityMicros) in new[]
        {
            (0UL, 0UL, 9UL, 8UL, 1_000UL),
            (800UL, 1_000UL, 9UL, 8UL, 1UL),
            (1_200UL, 1_000UL, 9UL, 8UL, 1UL),
            (600UL, 800UL, 10UL, 8UL, 250UL),
            (1UL, 1UL, 1UL, 2UL, 250UL),
        })
        {
            ulong referenceRttMicros = Math.Max(latestRttMicros, smoothedRttMicros);
            ulong expectedLossDelayMicros = Math.Max((referenceRttMicros * numerator) / denominator, granularityMicros);

            Assert.Equal(expectedLossDelayMicros, QuicRecoveryTiming.ComputeLossDelayMicros(
                latestRttMicros,
                smoothedRttMicros,
                numerator,
                denominator,
                granularityMicros));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryComputeRemainingLossDelayMicros_SchedulesRemainingTimeUntilLossDeadline()
    {
        foreach ((ulong packetSentAtMicros, ulong nowMicros, ulong latestRttMicros, ulong smoothedRttMicros, ulong expectedRemainingMicros) in new[]
        {
            (1_000UL, 2_000UL, 800UL, 1_000UL, 125UL),
            (1_000UL, 2_125UL, 800UL, 1_000UL, 0UL),
            (10_000UL, 10_500UL, 1_200UL, 1_000UL, 850UL),
            (50_000UL, 50_999UL, 0UL, 0UL, 1UL),
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
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0004")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0005")]
    [Requirement("REQ-QUIC-RFC9002-S6P1P2-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LossDelayHelpers_RejectInvalidThresholdParameters()
    {
        foreach ((ulong numerator, ulong denominator, ulong granularityMicros, string expectedParamName) in new[]
        {
            (0UL, 8UL, 1_000UL, "timeThresholdNumerator"),
            (9UL, 0UL, 1_000UL, "timeThresholdDenominator"),
            (9UL, 8UL, 0UL, "timerGranularityMicros"),
        })
        {
            ArgumentOutOfRangeException lossDelayException = Assert.Throws<ArgumentOutOfRangeException>(() =>
                QuicRecoveryTiming.ComputeLossDelayMicros(
                    latestRttMicros: 800,
                    smoothedRttMicros: 1_000,
                    timeThresholdNumerator: numerator,
                    timeThresholdDenominator: denominator,
                    timerGranularityMicros: granularityMicros));

            Assert.Equal(expectedParamName, lossDelayException.ParamName);

            ArgumentOutOfRangeException remainingDelayException = Assert.Throws<ArgumentOutOfRangeException>(() =>
                QuicRecoveryTiming.TryComputeRemainingLossDelayMicros(
                    packetSentAtMicros: 1_000,
                    nowMicros: 2_000,
                    latestRttMicros: 800,
                    smoothedRttMicros: 1_000,
                    out _,
                    timeThresholdNumerator: numerator,
                    timeThresholdDenominator: denominator,
                    timerGranularityMicros: granularityMicros));

            Assert.Equal(expectedParamName, remainingDelayException.ParamName);
        }
    }
}
