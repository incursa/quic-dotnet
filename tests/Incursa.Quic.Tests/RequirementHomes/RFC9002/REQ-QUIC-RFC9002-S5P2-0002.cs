namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S5P2-0002")]
public sealed class REQ_QUIC_RFC9002_S5P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryUpdateFromAck_UpdatesMinRttWhenALaterSampleIsSmaller()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_100,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.Equal(900UL, estimator.LatestRttMicros);
        Assert.Equal(900UL, estimator.MinRttMicros);
        Assert.Equal(987UL, estimator.SmoothedRttMicros);
        Assert.Equal(400UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_DoesNotRaiseMinRttWhenALaterSampleIsLarger()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_500,
            ackReceivedAtMicros: 3_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_062UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryUpdateFromAck_LeavesMinRttUnchangedWhenALaterSampleMatchesIt()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_500,
            ackReceivedAtMicros: 2_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(375UL, estimator.RttVarMicros);
        Assert.True(estimator.HasRttSample);
    }
}
