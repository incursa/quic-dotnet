namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P2-0004")]
public sealed class REQ_QUIC_RFC9002_S6P2P2_0004
{
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
