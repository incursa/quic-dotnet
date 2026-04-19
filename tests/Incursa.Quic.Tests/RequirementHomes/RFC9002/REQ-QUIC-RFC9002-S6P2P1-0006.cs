namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0006">A sender SHOULD restart its PTO timer every time an ack-eliciting packet is sent or acknowledged, or when Initial or Handshake keys are discarded.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0006")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryArmProbeTimeout_RestartsThePtoAfterAnAckElicitingSend()
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

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

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

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_RestartsThePtoAfterInitialKeysAreDiscarded()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial)));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.Equal(15_000UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);

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

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryArmProbeTimeout_PreservesAZeroBackoffWhenRestarted()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
    }
}
