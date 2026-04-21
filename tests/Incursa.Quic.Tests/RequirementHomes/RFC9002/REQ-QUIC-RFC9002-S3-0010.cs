namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0010">Data and frames that need reliable delivery MUST be sent in new packets as necessary.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0010")]
public sealed class REQ_QUIC_RFC9002_S3_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryTimerExpired_RetransmitsLostHandshakeCryptoInANewPacket()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-130535069-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\server\qlog\85c96da7a37deaaf.sqlog
        // The live server buffered later 1-RTT packets with trigger=keys_unavailable because the
        // client kept re-sending the same Handshake packet bytes instead of rebuilding the CRYPTO
        // retransmission in a fresh packet.
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial();
        QuicHandshakeFlowCoordinator coordinator = new();

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        byte[] handshakeCrypto = CreateSequentialBytes(0x70, 24);
        QuicConnectionTransitionResult sendResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: handshakeCrypto)),
            nowTicks: 4);

        Assert.True(sendResult.StateChanged);
        QuicConnectionSendDatagramEffect originalSendEffect = Assert.Single(
            sendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> originalTrackedPacket =
            FindTrackedPacket(runtime, originalSendEffect.Datagram);
        Assert.Equal(QuicPacketNumberSpace.Handshake, originalTrackedPacket.Key.PacketNumberSpace);

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] probeEffects = timerResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(probeEffects);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> probeTrackedPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && entry.Value.ProbePacket);
        ReadOnlyMemory<byte> probeDatagram = probeTrackedPacket.Value.PacketBytes;
        Assert.Contains(
            probeEffects,
            sendEffect => sendEffect.Datagram.Span.SequenceEqual(probeDatagram.Span));
        Assert.False(
            originalSendEffect.Datagram.Span.SequenceEqual(probeDatagram.Span),
            "Handshake CRYPTO repair must be sent in a fresh packet rather than reusing the original protected bytes.");

        Assert.True(coordinator.TryOpenHandshakePacket(
            probeDatagram.Span,
            handshakeMaterial,
            out byte[] openedProbePacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedProbePacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame retransmittedCryptoFrame,
            out int bytesConsumed));
        Assert.True(bytesConsumed > 0);
        Assert.Equal(0UL, retransmittedCryptoFrame.Offset);
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(retransmittedCryptoFrame.CryptoData));

        Assert.Equal(QuicPacketNumberSpace.Handshake, probeTrackedPacket.Key.PacketNumberSpace);
        Assert.NotEqual(originalTrackedPacket.Key.PacketNumber, probeTrackedPacket.Key.PacketNumber);
        Assert.Equal(
            probeTrackedPacket.Key.PacketNumber,
            ReadLongHeaderPacketNumber(openedProbePacket, payloadOffset));
    }

    private static KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> FindTrackedPacket(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram)
    {
        return Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(datagram.Span));
    }

    private static ulong ReadLongHeaderPacketNumber(byte[] openedPacket, int payloadOffset)
    {
        return QuicS17P1TestSupport.ReadPacketNumber(openedPacket.AsSpan(payloadOffset - sizeof(uint), sizeof(uint)));
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[1200]),
            nowTicks: 0).StateChanged);

        return runtime;
    }

    private static QuicTlsPacketProtectionMaterial CreateHandshakeMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        return material;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }

    private sealed class FakeMonotonicClock(long ticks) : IMonotonicClock
    {
        public long Ticks { get; } = ticks;

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
