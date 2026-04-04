namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP1-0003")]
public sealed class REQ_QUIC_RFC9002_SAP1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordProcessedPacket_PreservesPerPacketRecoveryFieldsInAckFrames()
    {
        QuicAckGenerationState tracker = new();

        tracker.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            8,
            ackEliciting: true,
            receivedAtMicros: 1_000,
            congestionExperienced: true,
            ecnCounts: new QuicEcnCounts(11, 12, 13));

        Assert.True(tracker.ShouldSendAckImmediately(QuicPacketNumberSpace.ApplicationData));
        Assert.True(tracker.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 4_000,
            out QuicAckFrame frame));

        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(8UL, frame.LargestAcknowledged);
        Assert.Equal(3_000UL, frame.AckDelay);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(11UL, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(12UL, frame.EcnCounts!.Value.Ect1Count);
        Assert.Equal(13UL, frame.EcnCounts!.Value.EcnCeCount);
    }
}
