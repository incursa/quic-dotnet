namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP2-0004")]
public sealed class REQ_QUIC_RFC9002_SAP2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Constructor_SeedsTheEstimatorWithTheRecommendedInitialRtt()
    {
        Assert.Equal(333_000UL, QuicRttEstimator.DefaultInitialRttMicros);

        QuicRttEstimator estimator = new();

        Assert.Equal(333_000UL, estimator.InitialRttMicros);
        Assert.Equal(333_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(166_500UL, estimator.RttVarMicros);
        Assert.False(estimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Constructor_KeepsACustomInitialRttInsteadOfFallingBackToTheDefault()
    {
        QuicRttEstimator estimator = new(initialRttMicros: 123_000);

        Assert.Equal(123_000UL, estimator.InitialRttMicros);
        Assert.NotEqual(QuicRttEstimator.DefaultInitialRttMicros, estimator.InitialRttMicros);
        Assert.Equal(123_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(61_500UL, estimator.RttVarMicros);
        Assert.False(estimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void Constructor_HandlesTheSmallestValidInitialRtt()
    {
        QuicRttEstimator estimator = new(initialRttMicros: 1);

        Assert.Equal(1UL, estimator.InitialRttMicros);
        Assert.Equal(1UL, estimator.SmoothedRttMicros);
        Assert.Equal(0UL, estimator.RttVarMicros);
        Assert.False(estimator.HasRttSample);
    }
}
