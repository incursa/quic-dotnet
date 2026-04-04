namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P3-0005")]
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
