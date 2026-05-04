namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P1-0002")]
public sealed class REQ_QUIC_RFC9000_S19P3P1_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AckGeneration_RepeatsAckRangesUntilCarrierPacketIsAcknowledged()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(QuicPacketNumberSpace.ApplicationData, packetNumber: 4, ackEliciting: true, receivedAtMicros: 1_000);

        Assert.True(state.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1_100, out QuicAckFrame firstAck));
        state.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 10,
            firstAck,
            sentAtMicros: 1_200,
            ackOnlyPacket: false);

        Assert.True(state.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 1_300, out QuicAckFrame repeatedAck));
        Assert.Equal(firstAck.LargestAcknowledged, repeatedAck.LargestAcknowledged);
        Assert.Equal(firstAck.FirstAckRange, repeatedAck.FirstAckRange);
    }
}
