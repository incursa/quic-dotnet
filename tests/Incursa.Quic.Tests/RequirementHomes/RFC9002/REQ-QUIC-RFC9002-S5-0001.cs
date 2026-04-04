namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S5-0001")]
public sealed class REQ_QUIC_RFC9002_S5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryUpdateFromAck_ComputesTheInitialRttSampleAndDerivedValues()
    {
        QuicRttEstimator estimator = new();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 1_000,
            ackReceivedAtMicros: 2_500,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_500UL, estimator.MinRttMicros);
        Assert.Equal(1_500UL, estimator.SmoothedRttMicros);
        Assert.Equal(750UL, estimator.RttVarMicros);
    }
}
