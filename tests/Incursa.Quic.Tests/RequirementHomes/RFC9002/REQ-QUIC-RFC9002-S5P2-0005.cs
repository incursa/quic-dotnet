namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S5P2-0005")]
public sealed class REQ_QUIC_RFC9002_S5P2_0005
{
    public static TheoryData<RefreshMinRttCase> RefreshMinRttCases => new()
    {
        new(1_800),
        new(900),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void RefreshMinRttFromLatestSample_AllowsExplicitMinRttReestablishment()
    {
        QuicRttEstimator estimator = new();
        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.RefreshMinRttFromLatestSample(1_800);
        Assert.Equal(1_800UL, estimator.MinRttMicros);

        estimator.RefreshMinRttFromLatestSample(900);
        Assert.Equal(900UL, estimator.MinRttMicros);
    }

    [Theory]
    [MemberData(nameof(RefreshMinRttCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void RefreshMinRttFromLatestSample_ReestablishesTheMinimumRtt(RefreshMinRttCase scenario)
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);

        estimator.RefreshMinRttFromLatestSample(scenario.LatestRttMicros);

        Assert.Equal(scenario.LatestRttMicros, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void RefreshMinRttFromLatestSample_DoesNotInventAnRttSampleOnAColdEstimator()
    {
        QuicRttEstimator estimator = new();

        estimator.RefreshMinRttFromLatestSample(1_800);

        Assert.False(estimator.HasRttSample);
        Assert.Equal(1_800UL, estimator.MinRttMicros);
        Assert.Equal(0UL, estimator.LatestRttMicros);
        Assert.Equal(333_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(166_500UL, estimator.RttVarMicros);
    }

    public sealed record RefreshMinRttCase(ulong LatestRttMicros);
}
