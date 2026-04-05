namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S5P3-0003">Before handshake confirmation, an endpoint MAY ignore an RTT sample if adjusting the sample for acknowledgment delay would make it smaller than min_rtt.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S5P3-0003")]
public sealed class REQ_QUIC_RFC9002_S5P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryUpdateFromAck_DoesNotDropASampleWhenAckDelayWouldMakeTheAdjustedSampleSmallerThanMinRtt()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 600,
            handshakeConfirmed: false));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_062UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryUpdateFromAck_AllowsAnAdjustedSampleThatExactlyMatchesMinRtt()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 600,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 400,
            handshakeConfirmed: false));

        Assert.Equal(1_400UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(375UL, estimator.RttVarMicros);
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
