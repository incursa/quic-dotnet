namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0789")]
public sealed class REQ_QUIC_RFC9000_0789
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CryptoRetransmission_ClearsQueuedRepairWhenOriginalPacketIsAcknowledged()
    {
        using QuicConnectionRuntime runtime = CreateRuntimeWithHandshakeCrypto(
            cryptoOffset: 0,
            QuicS12P3TestSupport.CreateSequentialBytes(0xB0, 24),
            out _,
            out QuicConnectionSendDatagramEffect originalSendEffect);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> originalTrackedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, originalSendEffect.Datagram);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            originalTrackedPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Handshake,
            originalTrackedPacket.Key.PacketNumber,
            handshakeConfirmed: true));

        List<QuicConnectionEffect>? effects = [];
        Assert.False(QuicS13AckPiggybackTestSupport.InvokeTryFlushPendingRetransmissions(
            runtime,
            QuicPacketNumberSpace.Handshake,
            nowTicks: TimeSpan.TicksPerMillisecond,
            probePacket: true,
            ref effects));

        Assert.NotNull(effects);
        Assert.Empty(effects);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CryptoRetransmission_PreservesNonZeroCryptoOffset()
    {
        byte[] cryptoPrefix = QuicS12P3TestSupport.CreateSequentialBytes(0xC0, 17);
        using QuicConnectionRuntime runtime = CreateRuntimeWithHandshakeCrypto(
            cryptoOffset: 0,
            cryptoPrefix,
            out QuicTlsPacketProtectionMaterial material,
            out QuicConnectionSendDatagramEffect prefixSendEffect);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> prefixTrackedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, prefixSendEffect.Datagram);
        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Handshake,
            prefixTrackedPacket.Key.PacketNumber,
            handshakeConfirmed: true));

        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0xC0, 29);
        ulong cryptoOffset = (ulong)cryptoPrefix.Length;
        QuicConnectionTransitionResult sendResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 5,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: cryptoOffset,
                    CryptoData: cryptoPayload)),
            nowTicks: 5);
        QuicConnectionSendDatagramEffect originalSendEffect = Assert.Single(
            sendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> originalTrackedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, originalSendEffect.Datagram);
        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            originalTrackedPacket.Key.PacketNumber,
            handshakeConfirmed: true));

        List<QuicConnectionEffect>? effects = [];
        Assert.True(QuicS13AckPiggybackTestSupport.InvokeTryFlushPendingRetransmissions(
            runtime,
            QuicPacketNumberSpace.Handshake,
            nowTicks: TimeSpan.TicksPerMillisecond,
            probePacket: true,
            ref effects));

        QuicConnectionSendDatagramEffect retransmissionSendEffect = Assert.Single(
            effects!.OfType<QuicConnectionSendDatagramEffect>());
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryOpenHandshakePacket(
            retransmissionSendEffect.Datagram.Span,
            material,
            out byte[] openedRetransmissionPacket,
            out int payloadOffset,
            out int payloadLength));
        QuicS13AckPiggybackTestSupport.AssertPayloadStartsWithCryptoWithoutAck(
            openedRetransmissionPacket.AsSpan(payloadOffset, payloadLength),
            cryptoPayload,
            cryptoOffset);

        ulong rebuiltPacketNumber = QuicS13AckPiggybackTestSupport.ReadLongHeaderPacketNumber(
            openedRetransmissionPacket,
            payloadOffset);
        Assert.NotEqual(originalTrackedPacket.Key.PacketNumber, rebuiltPacketNumber);
        Assert.Equal(
            rebuiltPacketNumber,
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, retransmissionSendEffect.Datagram).Key.PacketNumber);
    }

    private static QuicConnectionRuntime CreateRuntimeWithHandshakeCrypto(
        ulong cryptoOffset,
        byte[] cryptoPayload,
        out QuicTlsPacketProtectionMaterial material,
        out QuicConnectionSendDatagramEffect sendEffect)
    {
        QuicConnectionRuntime runtime = QuicS13AckPiggybackTestSupport.CreateRuntimeWithActivePath();
        material = QuicS13AckPiggybackTestSupport.CreateHandshakeMaterial();
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));

        QuicConnectionTransitionResult sendResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: cryptoOffset,
                    CryptoData: cryptoPayload)),
            nowTicks: 4);
        sendEffect = Assert.Single(sendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        return runtime;
    }
}
