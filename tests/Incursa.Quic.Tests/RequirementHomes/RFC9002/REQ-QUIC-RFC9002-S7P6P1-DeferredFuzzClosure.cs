// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S7P6P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PersistentCongestionDurationUsesRttVarianceAndGranularity()
    {
        foreach ((ulong smoothedRttMicros, ulong rttVarMicros, ulong maxAckDelayMicros) in RepresentativeRttCases())
        {
            Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                out ulong durationMicros));

            ulong expectedReferenceRttMicros =
                smoothedRttMicros + Math.Max(rttVarMicros * 4, QuicRecoveryTiming.RecommendedTimerGranularityMicros)
                + maxAckDelayMicros;
            Assert.Equal(expectedReferenceRttMicros * 3, durationMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MaxAckDelayContributesToPersistentCongestionDuration()
    {
        foreach ((ulong smoothedRttMicros, ulong rttVarMicros, ulong maxAckDelayMicros) in RepresentativeRttCases())
        {
            Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros: 0,
                out ulong withoutAckDelayMicros));
            Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                out ulong withAckDelayMicros));

            Assert.Equal(maxAckDelayMicros * 3, withAckDelayMicros - withoutAckDelayMicros);
        }
    }

    private static (ulong SmoothedRttMicros, ulong RttVarMicros, ulong MaxAckDelayMicros)[] RepresentativeRttCases()
    {
        return
        [
            (1UL, 0UL, 0UL),
            (1_000UL, 0UL, 25UL),
            (1_000UL, 400UL, 500UL),
            (20_000UL, 5_000UL, 1_000UL),
        ];
    }
}
