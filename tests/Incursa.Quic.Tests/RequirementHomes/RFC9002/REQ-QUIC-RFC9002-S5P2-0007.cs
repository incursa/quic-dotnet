namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0007">Implementations SHOULD NOT refresh the min_rtt value too often.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P2-0007")]
public sealed class REQ_QUIC_RFC9002_S5P2_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RefreshMinRttFromLatestSample_ReestablishesMinRttWithoutAlteringDerivedState()
    {
        QuicRttEstimator estimator = new();
        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.RefreshMinRttFromLatestSample(1_800);

        Assert.Equal(1_800UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);

        estimator.RefreshMinRttFromLatestSample(900);

        Assert.Equal(900UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RefreshMinRttFromLatestSample_IsIdempotentWhenTheSameSampleIsReapplied()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        estimator.RefreshMinRttFromLatestSample(1_800);
        estimator.RefreshMinRttFromLatestSample(1_800);

        Assert.Equal(1_800UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);
    }
}
