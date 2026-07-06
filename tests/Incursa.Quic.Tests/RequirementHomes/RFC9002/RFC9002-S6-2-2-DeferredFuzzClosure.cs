// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S6_2_2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S6-2-2-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResumedConnectionCanSeedInitialRttFromPriorFinalSmoothedRtt()
    {
        foreach ((ulong previousSentAtMicros, ulong previousAckAtMicros) in new[]
        {
            (0UL, 1UL),
            (1_000UL, 124_000UL),
            (10_000UL, 343_000UL),
            (500_000UL, 1_500_000UL),
        })
        {
            QuicRttEstimator previousConnectionEstimator = new();

            Assert.True(previousConnectionEstimator.TryUpdateFromAck(
                previousSentAtMicros,
                previousAckAtMicros,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));

            ulong priorFinalSmoothedRttMicros = previousAckAtMicros - previousSentAtMicros;
            Assert.Equal(priorFinalSmoothedRttMicros, previousConnectionEstimator.SmoothedRttMicros);

            QuicRttEstimator resumedConnectionEstimator = new(previousConnectionEstimator.SmoothedRttMicros);

            Assert.False(resumedConnectionEstimator.HasRttSample);
            Assert.Equal(priorFinalSmoothedRttMicros, resumedConnectionEstimator.InitialRttMicros);
            Assert.Equal(priorFinalSmoothedRttMicros, resumedConnectionEstimator.SmoothedRttMicros);
            Assert.Equal(priorFinalSmoothedRttMicros / 2, resumedConnectionEstimator.RttVarMicros);
            Assert.Equal(0UL, resumedConnectionEstimator.LatestRttMicros);
            Assert.Equal(0UL, resumedConnectionEstimator.MinRttMicros);
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-2-2-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DefaultInitialRttIsUsedOnlyWhenNoExplicitInitialRttIsProvided()
    {
        Assert.Equal(333_000UL, QuicRttEstimator.DefaultInitialRttMicros);

        foreach (ulong explicitInitialRttMicros in new[]
        {
            1UL,
            123_000UL,
            QuicRttEstimator.DefaultInitialRttMicros,
            1_000_000UL,
        })
        {
            QuicRttEstimator explicitEstimator = new(explicitInitialRttMicros);

            Assert.Equal(explicitInitialRttMicros, explicitEstimator.InitialRttMicros);
            Assert.Equal(explicitInitialRttMicros, explicitEstimator.SmoothedRttMicros);
            Assert.Equal(explicitInitialRttMicros / 2, explicitEstimator.RttVarMicros);

            Assert.True(explicitEstimator.TryUpdateFromAck(
                largestAcknowledgedPacketSentAtMicros: 0,
                ackReceivedAtMicros: 1,
                largestAcknowledgedPacketNewlyAcknowledged: true,
                newlyAcknowledgedAckElicitingPacket: true));

            explicitEstimator.Reset();

            Assert.False(explicitEstimator.HasRttSample);
            Assert.Equal(explicitInitialRttMicros, explicitEstimator.InitialRttMicros);
            Assert.Equal(explicitInitialRttMicros, explicitEstimator.SmoothedRttMicros);
            Assert.Equal(explicitInitialRttMicros / 2, explicitEstimator.RttVarMicros);
        }

        QuicRttEstimator defaultEstimator = new();

        Assert.False(defaultEstimator.HasRttSample);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, defaultEstimator.InitialRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, defaultEstimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, defaultEstimator.RttVarMicros);
    }

    [Fact]
    [Requirement("RFC9002-S6-2-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PathChallengeResponseDelayCanSeedInitialRttForANewPath()
    {
        foreach ((ulong challengeSentAtMicros, ulong responseReceivedAtMicros) in new[]
        {
            (0UL, 1UL),
            (1_000UL, 2_750UL),
            (100_000UL, 433_000UL),
            (ulong.MaxValue - 1_000UL, ulong.MaxValue),
        })
        {
            Assert.True(QuicPathValidation.TryMeasurePathChallengeRoundTripMicros(
                challengeSentAtMicros,
                responseReceivedAtMicros,
                out ulong roundTripMicros));
            Assert.Equal(responseReceivedAtMicros - challengeSentAtMicros, roundTripMicros);

            QuicRttEstimator newPathEstimator = new(roundTripMicros);

            Assert.False(newPathEstimator.HasRttSample);
            Assert.Equal(roundTripMicros, newPathEstimator.InitialRttMicros);
            Assert.Equal(roundTripMicros, newPathEstimator.SmoothedRttMicros);
            Assert.Equal(roundTripMicros / 2, newPathEstimator.RttVarMicros);
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-2-2-P2-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PathChallengeResponseDelayMeasurementDoesNotCreateAnRttSample()
    {
        foreach ((ulong challengeSentAtMicros, ulong responseReceivedAtMicros, bool expectedMeasured) in new[]
        {
            (0UL, 0UL, true),
            (1_000UL, 999UL, false),
            (1_000UL, 2_750UL, true),
            (ulong.MaxValue - 1UL, ulong.MaxValue, true),
        })
        {
            QuicRttEstimator estimator = new();

            Assert.Equal(expectedMeasured, QuicPathValidation.TryMeasurePathChallengeRoundTripMicros(
                challengeSentAtMicros,
                responseReceivedAtMicros,
                out _));

            Assert.False(estimator.HasRttSample);
            Assert.Equal(0UL, estimator.LatestRttMicros);
            Assert.Equal(0UL, estimator.MinRttMicros);
            Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
            Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);
        }
    }
}
