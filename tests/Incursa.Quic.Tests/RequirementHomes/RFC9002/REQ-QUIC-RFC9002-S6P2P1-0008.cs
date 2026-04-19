namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0008">The PTO backoff factor MUST be reset when an acknowledgment is received.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0008")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcknowledgePacket_ResetsTheBackoffAfterAnAcknowledgment()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.Equal(15_000UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);
    }
}
