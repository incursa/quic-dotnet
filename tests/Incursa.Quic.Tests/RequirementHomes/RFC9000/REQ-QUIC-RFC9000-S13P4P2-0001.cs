namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2-0001")]
public sealed class REQ_QUIC_RFC9000_S13P4P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void SenderFlowController_ProcessesEcnInAckFrames()
    {
        QuicSenderFlowController sender = new();

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentBytes: 1_200,
            sentAtMicros: 1_100,
            ackEliciting: true);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = 2,
            AckDelay = 0,
            FirstAckRange = 1,
            AdditionalRanges = Array.Empty<QuicAckRange>(),
            EcnCounts = new QuicEcnCounts(0, 0, 1),
        };

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true,
            pacingLimited: true));

        Assert.True(sender.CongestionControlState.HasRecoveryStartTime);
        Assert.Equal(7_200UL, sender.CongestionControlState.CongestionWindowBytes);
        Assert.Equal(7_200UL, sender.CongestionControlState.SlowStartThresholdBytes);
    }
}
