namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2-0005">When Initial or Handshake keys are discarded, the PTO and loss detection timers MUST be reset.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P2-0005")]
public sealed class REQ_QUIC_RFC9002_S6P2P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_ResetsPtoStateWhenInitialKeysAreDiscarded()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: new byte[] { 0x01 }));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x02 }));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.Initial,
            nowMicros: 300,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: false));
        Assert.Equal(1, runtime.ProbeTimeoutCount);
        Assert.NotNull(runtime.LossDetectionDeadlineMicros);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));

        Assert.Equal(0, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPacketNumberSpace_LeavesPtoBackoffCountUnchangedWhenApplicationDataIsDiscarded()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x11 }));

        Assert.True(runtime.TryArmProbeTimeout(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 250,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 25_000,
            handshakeConfirmed: true));

        int probeTimeoutCountBeforeDiscard = runtime.ProbeTimeoutCount;

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData));
        Assert.Equal(probeTimeoutCountBeforeDiscard, runtime.ProbeTimeoutCount);
        Assert.Null(runtime.LossDetectionDeadlineMicros);
        Assert.Empty(runtime.SentPackets);
    }
}
