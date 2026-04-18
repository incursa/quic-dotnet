namespace Incursa.Quic.Tests;

public sealed class QuicRttEstimatorUnitTests
{
    [Fact]
    public void TryUpdateFromAck_InitializesTheEstimatorFromTheFirstSample()
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

    [Fact]
    public void TryUpdateFromAck_UsesThePeerAckDelayCapOnlyAfterHandshakeConfirmation()
    {
        QuicRttEstimator beforeHandshake = CreatePrimedEstimator();

        Assert.True(beforeHandshake.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 600,
            handshakeConfirmed: false,
            peerMaxAckDelayMicros: 200));

        Assert.Equal(1_500UL, beforeHandshake.LatestRttMicros);
        Assert.Equal(1_000UL, beforeHandshake.MinRttMicros);
        Assert.Equal(1_062UL, beforeHandshake.SmoothedRttMicros);
        Assert.Equal(500UL, beforeHandshake.RttVarMicros);

        QuicRttEstimator afterHandshake = CreatePrimedEstimator();

        Assert.True(afterHandshake.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 600,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 200));

        Assert.Equal(1_500UL, afterHandshake.LatestRttMicros);
        Assert.Equal(1_000UL, afterHandshake.MinRttMicros);
        Assert.Equal(1_037UL, afterHandshake.SmoothedRttMicros);
        Assert.Equal(450UL, afterHandshake.RttVarMicros);
    }

    [Fact]
    public void TryUpdateFromAck_DoesNotSubtractAckDelayWhenItWouldCrossBelowTheMinimumRtt()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 700,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 700));

        Assert.Equal(1_500UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.MinRttMicros);
        Assert.Equal(1_062UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void TryUpdateFromAck_IgnoresUpdatesThatAreNotNewlyAcknowledgedOrNotAckEliciting(
        bool largestAcknowledgedPacketNewlyAcknowledged,
        bool newlyAcknowledgedAckElicitingPacket)
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();
        ulong latestRttMicros = estimator.LatestRttMicros;
        ulong minRttMicros = estimator.MinRttMicros;
        ulong smoothedRttMicros = estimator.SmoothedRttMicros;
        ulong rttVarMicros = estimator.RttVarMicros;

        Assert.False(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 500,
            ackReceivedAtMicros: 2_000,
            largestAcknowledgedPacketNewlyAcknowledged: largestAcknowledgedPacketNewlyAcknowledged,
            newlyAcknowledgedAckElicitingPacket: newlyAcknowledgedAckElicitingPacket,
            ackDelayMicros: 300,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 200));

        Assert.True(estimator.HasRttSample);
        Assert.Equal(latestRttMicros, estimator.LatestRttMicros);
        Assert.Equal(minRttMicros, estimator.MinRttMicros);
        Assert.Equal(smoothedRttMicros, estimator.SmoothedRttMicros);
        Assert.Equal(rttVarMicros, estimator.RttVarMicros);
    }

    [Fact]
    public void RefreshMinRttFromLatestSample_AffectsTheNextAckUpdate()
    {
        QuicRttEstimator estimator = CreatePrimedEstimator();

        estimator.RefreshMinRttFromLatestSample(1_800);

        Assert.True(estimator.HasRttSample);
        Assert.Equal(1_800UL, estimator.MinRttMicros);
        Assert.Equal(1_000UL, estimator.LatestRttMicros);
        Assert.Equal(1_000UL, estimator.SmoothedRttMicros);
        Assert.Equal(500UL, estimator.RttVarMicros);

        Assert.True(estimator.TryUpdateFromAck(
            largestAcknowledgedPacketSentAtMicros: 400,
            ackReceivedAtMicros: 2_600,
            largestAcknowledgedPacketNewlyAcknowledged: true,
            newlyAcknowledgedAckElicitingPacket: true,
            ackDelayMicros: 500,
            handshakeConfirmed: true,
            peerMaxAckDelayMicros: 500));

        Assert.Equal(2_200UL, estimator.LatestRttMicros);
        Assert.Equal(1_800UL, estimator.MinRttMicros);
        Assert.Equal(1_150UL, estimator.SmoothedRttMicros);
        Assert.Equal(675UL, estimator.RttVarMicros);
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
