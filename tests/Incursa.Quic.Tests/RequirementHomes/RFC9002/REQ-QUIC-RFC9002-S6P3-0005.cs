// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-3-P3-S2-R01">The client MAY use this value in place of its default for the initial RTT estimate.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-3-P3-S2-R01")]
public sealed class REQ_QUIC_RFC9002_S6P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void RetryDerivedInitialRtt_RejectsAZeroLengthRetryMeasurement()
    {
        Assert.True(QuicRecoveryTiming.TryMeasureRetryRoundTripMicros(
            firstInitialPacketSentAtMicros: 2_000,
            retryReceivedAtMicros: 2_000,
            out ulong retryRoundTripMicros));

        Assert.Equal(0UL, retryRoundTripMicros);
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicRttEstimator(retryRoundTripMicros));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void RetryDerivedInitialRtt_SeedsTheEstimatorWithTheSmallestNonZeroMeasurement()
    {
        Assert.True(QuicRecoveryTiming.TryMeasureRetryRoundTripMicros(
            firstInitialPacketSentAtMicros: 2_000,
            retryReceivedAtMicros: 2_001,
            out ulong retryRoundTripMicros));

        QuicRttEstimator estimator = new(retryRoundTripMicros);

        Assert.Equal(1UL, retryRoundTripMicros);
        Assert.Equal(1UL, estimator.InitialRttMicros);
        Assert.Equal(1UL, estimator.SmoothedRttMicros);
        Assert.Equal(0UL, estimator.RttVarMicros);
        Assert.False(estimator.HasRttSample);
    }
}
