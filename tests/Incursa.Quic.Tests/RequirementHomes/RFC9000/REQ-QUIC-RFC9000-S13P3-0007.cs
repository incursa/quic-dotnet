namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0007">Data in CRYPTO frames for Initial and Handshake packets MUST be discarded when the keys for the corresponding packet number space are discarded.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0007")]
public sealed class REQ_QUIC_RFC9000_S13P3_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_RemovesQueuedInitialAndHandshakeCryptoRetransmissionData()
    {
        QuicConnectionSendRuntime runtime = new();
        TrackCryptoPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            QuicTlsEncryptionLevel.Initial,
            packetNumber: 1,
            cryptoSeed: 0x10);
        TrackCryptoPacket(
            runtime,
            QuicPacketNumberSpace.Handshake,
            QuicTlsEncryptionLevel.Handshake,
            packetNumber: 2,
            cryptoSeed: 0x20);

        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Initial, packetNumber: 1));
        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Handshake, packetNumber: 2, handshakeConfirmed: true));
        Assert.Equal(2, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retainedHandshake));
        Assert.Equal(QuicPacketNumberSpace.Handshake, retainedHandshake.PacketNumberSpace);
        AssertCryptoPayload(retainedHandshake.PlaintextPayload.Span, expectedCryptoSeed: 0x20);

        runtime.QueueRetransmission(retainedHandshake);
        Assert.True(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));
        Assert.DoesNotContain(runtime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPacketNumberSpace_DoesNotDiscardCryptoDataForOtherPacketNumberSpaces()
    {
        QuicConnectionSendRuntime runtime = new();
        TrackCryptoPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            QuicTlsEncryptionLevel.Initial,
            packetNumber: 1,
            cryptoSeed: 0x30);
        TrackCryptoPacket(
            runtime,
            QuicPacketNumberSpace.Handshake,
            QuicTlsEncryptionLevel.Handshake,
            packetNumber: 2,
            cryptoSeed: 0x40);

        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Initial, packetNumber: 1));
        Assert.True(runtime.TryRegisterLoss(QuicPacketNumberSpace.Handshake, packetNumber: 2, handshakeConfirmed: true));
        Assert.False(runtime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData));
        Assert.Equal(2, runtime.PendingRetransmissionCount);

        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan initialRetransmission));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialRetransmission.PacketNumberSpace);
        AssertCryptoPayload(initialRetransmission.PlaintextPayload.Span, expectedCryptoSeed: 0x30);

        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan handshakeRetransmission));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeRetransmission.PacketNumberSpace);
        AssertCryptoPayload(handshakeRetransmission.PlaintextPayload.Span, expectedCryptoSeed: 0x40);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TlsKeyDiscardUpdate_RemovesStillTrackedCryptoDataBeforeItCanBeQueuedForRetransmission()
    {
        using QuicConnectionRuntime runtime = QuicS13AckPiggybackTestSupport.CreateRuntimeWithActivePath();
        TrackCryptoPacket(
            runtime.SendRuntime,
            QuicPacketNumberSpace.Initial,
            QuicTlsEncryptionLevel.Initial,
            packetNumber: 9,
            cryptoSeed: 0x50);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 5,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysDiscarded,
                    QuicTlsEncryptionLevel.Initial)),
            nowTicks: 5);

        Assert.True(result.StateChanged);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Keys, key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.False(runtime.SendRuntime.TryRegisterLoss(QuicPacketNumberSpace.Initial, packetNumber: 9));
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    private static void TrackCryptoPacket(
        QuicConnectionSendRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        QuicTlsEncryptionLevel encryptionLevel,
        ulong packetNumber,
        byte cryptoSeed)
    {
        byte[] plaintextPayload = FormatCryptoPayload(
            offset: packetNumber * 8,
            CreateCryptoData(cryptoSeed));

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            PayloadBytes: (ulong)plaintextPayload.Length,
            SentAtMicros: 100 + packetNumber,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(encryptionLevel),
            PacketBytes: new byte[] { cryptoSeed },
            PlaintextPayload: plaintextPayload));
    }

    private static byte[] FormatCryptoPayload(ulong offset, byte[] cryptoData)
    {
        byte[] payload = new byte[32];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(offset, cryptoData),
            payload,
            out int bytesWritten));
        return payload.AsSpan(0, bytesWritten).ToArray();
    }

    private static void AssertCryptoPayload(ReadOnlySpan<byte> payload, byte expectedCryptoSeed)
    {
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            payload,
            out QuicCryptoFrame cryptoFrame,
            out int bytesConsumed));
        Assert.Equal(payload.Length, bytesConsumed);
        Assert.True(cryptoFrame.CryptoData.SequenceEqual(CreateCryptoData(expectedCryptoSeed)));
    }

    private static byte[] CreateCryptoData(byte seed) =>
    [
        seed,
        (byte)(seed + 1),
        (byte)(seed + 2),
    ];
}
