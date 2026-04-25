namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0010">An endpoint SHOULD send an ACK frame with other frames when there are new ack-eliciting packets to acknowledge.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0010")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_IncludesPendingAckFrameWithOutboundStreamFrame()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        QuicS13AckPiggybackTestSupport.RecordPendingApplicationAck(
            runtime,
            packetNumber: 9,
            receivedAtMicros: 10);

        byte[] streamData = Enumerable.Range(0, 40).Select(value => (byte)value).ToArray();
        await stream.WriteAsync(streamData, 0, streamData.Length);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> payload = payloadBytes;

        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(9UL, ackFrame.LargestAcknowledged);

        ReadOnlySpan<byte> streamPayload = QuicS13AckPiggybackTestSupport.SkipPadding(payload[ackBytesConsumed..]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(streamPayload, out QuicStreamFrame streamFrame));
        Assert.Equal((ulong)stream.Id, streamFrame.StreamId.Value);
        Assert.True(streamFrame.StreamData.SequenceEqual(streamData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task WriteAsync_DoesNotInventAckFrameWhenThereIsNoPendingAck()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] streamData = Enumerable.Range(0, 40).Select(value => (byte)(value + 1)).ToArray();
        await stream.WriteAsync(streamData, 0, streamData.Length);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> payload = payloadBytes;

        Assert.False(QuicFrameCodec.TryParseAckFrame(payload, out _, out _));
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame streamFrame));
        Assert.Equal((ulong)stream.Id, streamFrame.StreamId.Value);
        Assert.True(streamFrame.StreamData.SequenceEqual(streamData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewTokenEmissionOnValidatedPath_IncludesPendingAckFrame()
    {
        QuicConnectionRuntime runtime = QuicS9P3TokenEmissionTestSupport.CreateServerRuntimeReadyForTokenEmission();
        QuicConnectionPathIdentity validatedPath = QuicS9P3TokenEmissionTestSupport.ValidatedPath;
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicS13AckPiggybackTestSupport.RecordPendingApplicationAck(
            runtime,
            packetNumber: 13,
            receivedAtMicros: 19);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                validatedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            validatedPath,
            observedAtTicks: 30);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            validationResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> payload = payloadBytes;

        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(13UL, ackFrame.LargestAcknowledged);

        ReadOnlySpan<byte> tokenPayload = QuicS13AckPiggybackTestSupport.SkipPadding(payload[ackBytesConsumed..]);
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(tokenPayload, out QuicNewTokenFrame newTokenFrame, out int tokenBytesConsumed));
        Assert.True(newTokenFrame.Token.Length > 0);
        Assert.True(QuicS13AckPiggybackTestSupport.SkipPadding(tokenPayload[tokenBytesConsumed..]).IsEmpty);
        Assert.False(runtime.SendRuntime.FlowController.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 31,
            maxAckDelayMicros: 0));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NewTokenEmissionOnValidatedPath_DoesNotInventAckFrameWhenNoAckIsPending()
    {
        QuicConnectionRuntime runtime = QuicS9P3TokenEmissionTestSupport.CreateServerRuntimeReadyForTokenEmission();
        QuicConnectionPathIdentity validatedPath = QuicS9P3TokenEmissionTestSupport.ValidatedPath;
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                validatedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            validatedPath,
            observedAtTicks: 30);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            validationResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> payload = payloadBytes;

        Assert.False(QuicFrameCodec.TryParseAckFrame(payload, out _, out _));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(payload, out QuicNewTokenFrame newTokenFrame, out int tokenBytesConsumed));
        Assert.True(newTokenFrame.Token.Length > 0);
        Assert.True(QuicS13AckPiggybackTestSupport.SkipPadding(payload[tokenBytesConsumed..]).IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialCryptoFlush_IncludesPendingInitialAckFrame()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateClientRuntime();
        QuicS13AckPiggybackTestSupport.RecordPendingAck(
            runtime,
            QuicPacketNumberSpace.Initial,
            packetNumber: 21,
            receivedAtMicros: 0);

        QuicConnectionTransitionResult bootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: TimeSpan.TicksPerMillisecond,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(
                    QuicS17P2P5P2TestSupport.InitialSourceConnectionId)),
            nowTicks: TimeSpan.TicksPerMillisecond);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            QuicS17P2P3TestSupport.GetInitialSendEffects(bootstrapResult.Effects));
        ReadOnlySpan<byte> payload = OpenClientInitialPayload(sendEffect);

        QuicS13AckPiggybackTestSupport.AssertPayloadStartsWithAckThenCrypto(
            payload,
            expectedLargestAcknowledged: 21,
            expectedCryptoPayload: ReadOnlySpan<byte>.Empty,
            expectedCryptoOffset: 0);
        Assert.False(runtime.SendRuntime.FlowController.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.Initial,
            nowMicros: 1,
            maxAckDelayMicros: 0));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandshakeCryptoFlush_IncludesPendingHandshakeAckFrame()
    {
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.20", "198.51.100.40", 443, 12345);
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(QuicS17P2P2TestSupport.InitialDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(QuicS17P2P2TestSupport.InitialSourceConnectionId));
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 0).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);

        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial material));
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 0).StateChanged);

        QuicS13AckPiggybackTestSupport.RecordPendingAck(
            runtime,
            QuicPacketNumberSpace.Handshake,
            packetNumber: 34,
            receivedAtMicros: 0);

        byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x40, 32);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: TimeSpan.TicksPerMillisecond,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    EncryptionLevel: QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: cryptoPayload)),
            nowTicks: TimeSpan.TicksPerMillisecond);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        ReadOnlySpan<byte> payload = OpenHandshakePayload(sendEffect, material);

        QuicS13AckPiggybackTestSupport.AssertPayloadStartsWithAckThenCrypto(
            payload,
            expectedLargestAcknowledged: 34,
            cryptoPayload,
            expectedCryptoOffset: 0);
        Assert.False(runtime.SendRuntime.FlowController.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.Handshake,
            nowMicros: 1,
            maxAckDelayMicros: 0));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LongHeaderCryptoPacketBuilders_DoNotInventAckFramesWhenNoAckPrefixIsProvided()
    {
        byte[] initialCryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x50, 24);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientInitialProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverInitialProtection));
        QuicHandshakeFlowCoordinator initialCoordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();

        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
            initialCryptoPayload,
            cryptoPayloadOffset: 3,
            clientInitialProtection,
            out byte[] protectedInitialPacket));
        Assert.True(initialCoordinator.TryOpenInitialPacket(
            protectedInitialPacket,
            serverInitialProtection,
            out byte[] openedInitialPacket,
            out int initialPayloadOffset,
            out int initialPayloadLength));
        QuicS13AckPiggybackTestSupport.AssertPayloadStartsWithCryptoWithoutAck(
            openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength),
            initialCryptoPayload,
            expectedCryptoOffset: 3);

        byte[] handshakeCryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x60, 24);
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));
        QuicHandshakeFlowCoordinator handshakeCoordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();

        Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
            handshakeCryptoPayload,
            cryptoPayloadOffset: 5,
            handshakeMaterial,
            out byte[] protectedHandshakePacket));
        Assert.True(handshakeCoordinator.TryOpenHandshakePacket(
            protectedHandshakePacket,
            handshakeMaterial,
            out byte[] openedHandshakePacket,
            out int handshakePayloadOffset,
            out int handshakePayloadLength));
        QuicS13AckPiggybackTestSupport.AssertPayloadStartsWithCryptoWithoutAck(
            openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
            handshakeCryptoPayload,
            expectedCryptoOffset: 5);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeaderAckPrefixRoundTripsAcrossInitialAndHandshakeCryptoPayloads()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientInitialProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverInitialProtection));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));

        for (int length = 1; length <= 97; length += 12)
        {
            byte[] ackPayload = QuicS13AckPiggybackTestSupport.CreateAckFramePayload((ulong)length);
            byte[] cryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x20 + length), length);

            QuicHandshakeFlowCoordinator initialCoordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
            Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
                cryptoPayload,
                cryptoPayloadOffset: (ulong)(length % 7),
                ackPayload,
                clientInitialProtection,
                out byte[] protectedInitialPacket));
            Assert.True(initialCoordinator.TryOpenInitialPacket(
                protectedInitialPacket,
                serverInitialProtection,
                out byte[] openedInitialPacket,
                out int initialPayloadOffset,
                out int initialPayloadLength));
            QuicS13AckPiggybackTestSupport.AssertPayloadStartsWithAckThenCrypto(
                openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength),
                expectedLargestAcknowledged: (ulong)length,
                cryptoPayload,
                expectedCryptoOffset: (ulong)(length % 7));

            QuicHandshakeFlowCoordinator handshakeCoordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
            Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
                cryptoPayload,
                cryptoPayloadOffset: (ulong)(length % 11),
                ackPayload,
                handshakeMaterial,
                out byte[] protectedHandshakePacket));
            Assert.True(handshakeCoordinator.TryOpenHandshakePacket(
                protectedHandshakePacket,
                handshakeMaterial,
                out byte[] openedHandshakePacket,
                out int handshakePayloadOffset,
                out int handshakePayloadLength));
            QuicS13AckPiggybackTestSupport.AssertPayloadStartsWithAckThenCrypto(
                openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
                expectedLargestAcknowledged: (ulong)length,
                cryptoPayload,
                expectedCryptoOffset: (ulong)(length % 11));
        }
    }

    private static ReadOnlySpan<byte> OpenClientInitialPayload(QuicConnectionSendDatagramEffect sendEffect)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection serverInitialProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryOpenInitialPacket(
            sendEffect.Datagram.Span,
            serverInitialProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
    }

    private static ReadOnlySpan<byte> OpenHandshakePayload(
        QuicConnectionSendDatagramEffect sendEffect,
        QuicTlsPacketProtectionMaterial material)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryOpenHandshakePacket(
            sendEffect.Datagram.Span,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        internal FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
