namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0004">In addition to sending data in the packet number space for which the timer expired, the sender SHOULD send ack-eliciting packets from other packet number spaces with in-flight data, coalescing packets if possible.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0004")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_ReturnsTheEarlierDeadline()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: 3_000,
            handshakeProbeTimeoutMicros: 2_500,
            out ulong selectedProbeTimeoutMicros));

        Assert.Equal(2_500UL, selectedProbeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_ReturnsFalseWhenBothDeadlinesAreMissing()
    {
        Assert.False(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: null,
            handshakeProbeTimeoutMicros: null,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectInitialOrHandshakeProbeTimeoutMicros_UsesTheRemainingDeadlineWhenOneSpaceIsMissing()
    {
        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: null,
            handshakeProbeTimeoutMicros: 2_500,
            out ulong selectedHandshakeProbeTimeoutMicros));

        Assert.Equal(2_500UL, selectedHandshakeProbeTimeoutMicros);

        Assert.True(QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
            initialProbeTimeoutMicros: 3_000,
            handshakeProbeTimeoutMicros: null,
            out ulong selectedInitialProbeTimeoutMicros));

        Assert.Equal(3_000UL, selectedInitialProbeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandleRecoveryTimerExpired_SendsAHandshakeProbeBeforeFallingBackToPing()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial();
        QuicHandshakeFlowCoordinator coordinator = new();

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        byte[] firstHandshakeCrypto = CreateSequentialBytes(0x40, 16);
        QuicConnectionTransitionResult firstSendResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: firstHandshakeCrypto)),
            nowTicks: 4);

        Assert.True(firstSendResult.StateChanged);
        QuicConnectionSendDatagramEffect firstSendEffect = Assert.Single(
            firstSendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(coordinator.TryOpenHandshakePacket(
            firstSendEffect.Datagram.Span,
            handshakeMaterial,
            out byte[] openedFirstPacket,
            out int firstPayloadOffset,
            out int firstPayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedFirstPacket.AsSpan(firstPayloadOffset, firstPayloadLength),
            out QuicCryptoFrame firstCryptoFrame,
            out int firstBytesConsumed));
        Assert.Equal(0UL, firstCryptoFrame.Offset);
        Assert.True(firstHandshakeCrypto.AsSpan().SequenceEqual(firstCryptoFrame.CryptoData));
        Assert.True(firstBytesConsumed > 0);

        QuicConnectionTransitionResult recoveryArmResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 5,
                runtime.ActivePath!.Value.Identity,
                new byte[] { 0x00 }),
            nowTicks: 5);

        Assert.True(recoveryArmResult.StateChanged);
        QuicConnectionArmTimerEffect recoveryArm = Assert.Single(
            recoveryArmResult.Effects.OfType<QuicConnectionArmTimerEffect>(),
            effect => effect.TimerKind == QuicConnectionTimerKind.Recovery);
        long recoveryDueTicks = recoveryArm.Priority.DueTicks;
        ulong recoveryGeneration = recoveryArm.Generation;

        byte[] secondHandshakeCrypto = CreateSequentialBytes(0x60, 16);
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.CryptoDataAvailable,
            QuicTlsEncryptionLevel.Handshake,
            CryptoDataOffset: (ulong)firstHandshakeCrypto.Length,
            CryptoData: secondHandshakeCrypto)));
        Assert.Equal(secondHandshakeCrypto.Length, runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(coordinator.TryOpenHandshakePacket(
            sendEffect.Datagram.Span,
            handshakeMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame cryptoFrame,
            out int bytesConsumed));
        Assert.Equal((ulong)firstHandshakeCrypto.Length, cryptoFrame.Offset);
        Assert.True(secondHandshakeCrypto.AsSpan().SequenceEqual(cryptoFrame.CryptoData));
        Assert.True(bytesConsumed > 0);
        Assert.Equal(0, runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes);
        QuicConnectionArmTimerEffect rearmedRecovery = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionArmTimerEffect>(),
            effect => effect.TimerKind == QuicConnectionTimerKind.Recovery);
        Assert.True(rearmedRecovery.Generation > recoveryGeneration);
        Assert.True(rearmedRecovery.Priority.DueTicks > recoveryDueTicks);
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
