namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P2-0006">Endpoints MAY reestablish min_rtt at other times in the connection, such as when traffic volume is low and an acknowledgment is received with a low acknowledgment delay.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P2-0006")]
public sealed class REQ_QUIC_RFC9002_S5P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RefreshMinRttFromLatestSample_AllowsOpportunisticReestablishmentAfterALowDelayAck()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 50,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 200));

        estimator.RefreshMinRttFromLatestSample(900);

        Assert.True(estimator.HasRttSample);
        Assert.Equal(900UL, estimator.MinRttMicros);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_056UL, estimator.SmoothedRttMicros);
        Assert.Equal(487UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryUpdateFromAck_LeavesMinRttAtTheCurrentFloorWhenTheCallerDoesNotRefreshIt()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 50,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 200));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_056UL, estimator.SmoothedRttMicros);
        Assert.Equal(487UL, estimator.RttVarMicros);
    }

    private static QuicRttEstimator CreatePrimedEstimator()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 0,
            ackReceivedAtMicros: 1_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        return estimator;
    }
}
