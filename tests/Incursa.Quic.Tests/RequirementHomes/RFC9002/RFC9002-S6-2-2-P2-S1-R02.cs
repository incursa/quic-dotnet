// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-2-2-P2-S1-R02">That delay SHOULD NOT be considered an RTT sample.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-2-2-P2-S1-R02")]
public sealed class REQ_QUIC_RFC9002_S6P2P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryMeasurePathChallengeRoundTripMicros_MeasuresDelayWithoutUpdatingTheRttEstimator()
    {
        QuicRttEstimator estimator = new();

        Assert.True(QuicPathValidation.TryMeasurePathChallengeRoundTripMicros(
            pathChallengeSentAtMicros: 1_000,
            pathResponseReceivedAtMicros: 2_750,
            out ulong roundTripMicros));

        Assert.Equal(1_750UL, roundTripMicros);
        Assert.False(estimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryMeasurePathChallengeRoundTripMicros_DoesNotCreateAnRttSample()
    {
        QuicRttEstimator estimator = new();

        Assert.True(QuicPathValidation.TryMeasurePathChallengeRoundTripMicros(
            pathChallengeSentAtMicros: 1_000,
            pathResponseReceivedAtMicros: 2_750,
            out ulong roundTripMicros));

        Assert.Equal(1_750UL, roundTripMicros);
        Assert.False(estimator.HasRttSample);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(QuicRttEstimator.DefaultInitialRttMicros / 2, estimator.RttVarMicros);
    }
}
