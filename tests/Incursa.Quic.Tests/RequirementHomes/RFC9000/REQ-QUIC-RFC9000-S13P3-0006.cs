namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P3-0006")]
public sealed class REQ_QUIC_RFC9000_S13P3_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CryptoRetransmission_RebuildsCryptoDataInFreshPacketWithTransientAckPrefix()
    {
        using QuicConnectionRuntime runtime = QuicS13AckPiggybackTestSupport.CreateRuntimeWithActivePath();
        QuicTlsPacketProtectionMaterial material = QuicS13AckPiggybackTestSupport.CreateHandshakeMaterial();
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));

        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0xA0, 28);
        QuicConnectionTransitionResult sendResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: cryptoPayload)),
            nowTicks: 4);
        QuicConnectionSendDatagramEffect originalSendEffect = Assert.Single(
            sendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> originalTrackedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, originalSendEffect.Datagram);
        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            originalTrackedPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        QuicS13AckPiggybackTestSupport.RecordPendingAck(
            runtime,
            QuicPacketNumberSpace.Handshake,
            packetNumber: 233,
            receivedAtMicros: 1);

        List<QuicConnectionEffect>? effects = [];
        Assert.True(QuicS13AckPiggybackTestSupport.InvokeTryFlushPendingRetransmissions(
            runtime,
            QuicPacketNumberSpace.Handshake,
            nowTicks: TimeSpan.TicksPerMillisecond,
            probePacket: true,
            ref effects));

        QuicConnectionSendDatagramEffect retransmissionSendEffect = Assert.Single(
            effects!.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(coordinator.TryOpenHandshakePacket(
            retransmissionSendEffect.Datagram.Span,
            material,
            out byte[] openedRetransmissionPacket,
            out int payloadOffset,
            out int payloadLength));
        QuicS13AckPiggybackTestSupport.AssertPayloadStartsWithAckThenCrypto(
            openedRetransmissionPacket.AsSpan(payloadOffset, payloadLength),
            expectedLargestAcknowledged: 233,
            cryptoPayload,
            expectedCryptoOffset: 0);

        ulong rebuiltPacketNumber = QuicS13AckPiggybackTestSupport.ReadLongHeaderPacketNumber(
            openedRetransmissionPacket,
            payloadOffset);
        Assert.NotEqual(originalTrackedPacket.Key.PacketNumber, rebuiltPacketNumber);
        Assert.Equal(
            rebuiltPacketNumber,
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, retransmissionSendEffect.Datagram).Key.PacketNumber);
    }
}
