namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P2-0002")]
public sealed class REQ_QUIC_RFC9002_S6P2P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void Reset_DoesNotFallBackTo333MillisecondsWhenANonDefaultInitialRttWasConfigured()
    {
        QuicRttEstimator estimator = new(initialRttMicros: 123_000);

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 1_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.Reset();

        Assert.Equal(123_000UL, estimator.InitialRttMicros);
        Assert.NotEqual(QuicRttEstimator.DefaultInitialRttMicros, estimator.InitialRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(123_000UL, estimator.SmoothedRttMicros);
        Assert.NotEqual(QuicRttEstimator.DefaultInitialRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(61_500UL, estimator.RttVarMicros);
        Assert.False(estimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void ConstructorAndReset_UseTheExact333MillisecondDefaultAtTheBoundary()
    {
        Assert.Equal(333_000UL, QuicRttEstimator.DefaultInitialRttMicros);

        QuicRttEstimator estimator = new();

        Assert.Equal(333_000UL, estimator.InitialRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(333_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(166_500UL, estimator.RttVarMicros);
        Assert.False(estimator.HasRttSample);

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.Reset();

        Assert.Equal(333_000UL, estimator.InitialRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(0UL, estimator.MinRttMicros);
        Assert.Equal(333_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(166_500UL, estimator.RttVarMicros);
        Assert.False(estimator.HasRttSample);
    }
}
