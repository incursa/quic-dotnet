namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0009">A client that is not yet certain that the server has finished validating its address MUST NOT reset the PTO backoff factor on receiving acknowledgments in Initial packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0009")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgePacket_DoesNotResetOnAnUnvalidatedInitialAcknowledgment()
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
            QuicPacketNumberSpace.Initial,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial)));

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

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Initial,
            1,
            handshakeConfirmed: false));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false));

        Assert.Equal(3, runtime.ProbeTimeoutCount);
        Assert.Equal(30_000UL, runtime.LossDetectionDeadlineMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcknowledgePacket_ResetsOnAValidatedInitialAcknowledgment()
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
            QuicPacketNumberSpace.Initial,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial)));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false));

        Assert.Equal(2, runtime.ProbeTimeoutCount);
        Assert.Equal(15_000UL, runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Initial,
            1,
            handshakeConfirmed: true));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 0,
            smoothedRttMicros: 2_500,
            rttVarMicros: 1_250,
            maxAckDelayMicros: 0,
            handshakeConfirmed: false));

        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.Equal(7_500UL, runtime.LossDetectionDeadlineMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAcknowledgePacket_PreservesAZeroBackoffOnAnUnvalidatedInitialAcknowledgment()
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
            QuicPacketNumberSpace.Initial,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 0,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial)));

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Initial,
            1,
            handshakeConfirmed: false));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
    }
}
