using System.Reflection;
using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0004">In addition to sending data in the packet number space for which the timer expired, the sender SHOULD send ack-eliciting packets from other packet number spaces with in-flight data, coalescing packets if possible.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0004")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0004
{
    private static readonly byte[] ApplicationPacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    private static readonly byte[] ApplicationPacketSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

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
    public void HandleRecoveryTimerExpired_SendsAHandshakeProbeWithoutFallingBackToPing()
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

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        byte[] secondHandshakeCrypto = CreateSequentialBytes(0x60, 16);
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.CryptoDataAvailable,
            QuicTlsEncryptionLevel.Handshake,
            CryptoDataOffset: (ulong)firstHandshakeCrypto.Length,
            CryptoData: secondHandshakeCrypto)));
        Assert.Equal(secondHandshakeCrypto.Length, runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] sendEffects = timerResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.Single(sendEffects);

        QuicConnectionSendDatagramEffect sendEffect = FindHandshakeProbeEffect(
            sendEffects,
            coordinator,
            handshakeMaterial);
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
        Assert.True(bytesConsumed > 0);
        QuicConnectionSentPacket sentProbePacket = Assert.Single(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
        Assert.True(sentProbePacket.ProbePacket);
        QuicConnectionArmTimerEffect rearmedRecovery = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionArmTimerEffect>(),
            effect => effect.TimerKind == QuicConnectionTimerKind.Recovery);
        Assert.True(rearmedRecovery.Generation > recoveryGeneration);
        Assert.True(rearmedRecovery.Priority.DueTicks > recoveryDueTicks.Value);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandleRecoveryTimerExpired_UsesTheSecondProbeForHandshakeWhenInitialPacketsAreStillOutstanding()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-multiconnect-post-idletimerfix\20260421-102640827-client-chrome
        //   docker logs client: the managed multiconnect client opened stream 1 and sent the HTTP/0.9 request line.
        //   docker logs server: quic-go reached 1-RTT read keys, then timed out waiting for further progress.
        //   live client qlog client-multiconnect-2e78ba5f48ba4329b23418af1aa554a9.qlog:
        //     event 8  -> client Handshake packet sent
        //     events 9-24 -> repeated client Initial retransmissions without a follow-up Handshake probe
        // Keep the second PTO datagram available for a Handshake probe when Initial still has in-flight packets.
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[1200]),
            nowTicks: 1).StateChanged);
        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial();
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        byte[] handshakeCrypto = CreateSequentialBytes(0x80, 24);
        QuicConnectionTransitionResult handshakeSendResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: handshakeCrypto)),
            nowTicks: 4);

        Assert.True(handshakeSendResult.StateChanged);
        QuicConnectionSendDatagramEffect firstHandshakeSendEffect = Assert.Single(
            handshakeSendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(coordinator.TryOpenHandshakePacket(
            firstHandshakeSendEffect.Datagram.Span,
            handshakeMaterial,
            out byte[] openedFirstHandshakePacket,
            out int firstPayloadOffset,
            out int firstPayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedFirstHandshakePacket.AsSpan(firstPayloadOffset, firstPayloadLength),
            out QuicCryptoFrame firstHandshakeCryptoFrame,
            out int firstHandshakeBytesConsumed));
        Assert.Equal(0UL, firstHandshakeCryptoFrame.Offset);
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(firstHandshakeCryptoFrame.CryptoData));
        Assert.True(firstHandshakeBytesConsumed > 0);

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] sendEffects = timerResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.Equal(2, sendEffects.Length);

        QuicConnectionSendDatagramEffect initialProbeEffect = FindInitialProbeEffect(sendEffects);
        QuicConnectionSendDatagramEffect handshakeProbeEffect = FindHandshakeCryptoProbeEffect(
            sendEffects,
            coordinator,
            handshakeMaterial,
            handshakeCrypto);

        Assert.NotSame(initialProbeEffect, handshakeProbeEffect);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(initialProbeEffect.Datagram.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(handshakeProbeEffect.Datagram.Span));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandleRecoveryTimerExpired_CoalescesInitialAndHandshakeProbesWhenTheObservedPathCanCarryBoth()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-multiconnect-post-coalescedprobe-dcidfix\20260421-111217232-client-chrome
        //   live-server-qlog\7a6cb9382ee5954d.sqlog:
        //     datagram_id 1544157299 received client Initial dcid=3bf22bcc followed by a dropped Handshake
        //     with dcid=d731074f and trigger=unknown_connection_id.
        //   The peer had already issued a NEW_CONNECTION_ID, so the runtime's mutable destination-CID state
        //   diverged from the handshake-space destination used by the outstanding Handshake retransmission.
        // Preserve Initial+Handshake ordering by coalescing the two crypto-space PTO retransmissions
        // and pin the rebuilt client Initial probe to the outstanding Handshake packet's destination CID.
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.10", RemotePort: 443);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                pathIdentity,
                new byte[1200]),
            nowTicks: 1).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                pathIdentity,
                new byte[1280]),
            nowTicks: 2).StateChanged);
        Assert.Equal(1280UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        byte[] handshakeDestinationConnectionId = [0xAD, 0x9D, 0xCC, 0x5E];
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(handshakeDestinationConnectionId));

        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial();
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(handshakeDestinationConnectionId));

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        byte[] handshakeCrypto = CreateSequentialBytes(0xA0, 24);
        QuicConnectionTransitionResult handshakeSendResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: handshakeCrypto)),
            nowTicks: 4);

        Assert.True(handshakeSendResult.StateChanged);

        // Mimic the later NEW_CONNECTION_ID drift from the live multiconnect run. The recovery path
        // must still rebuild the Initial probe for the handshake-space destination captured on the
        // outstanding Handshake retransmission, not for the newer peer destination CID.
        byte[] rotatedPeerDestinationConnectionId = [0x3B, 0xF2, 0x2B, 0xCC];
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(rotatedPeerDestinationConnectionId));

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect coalescedProbeEffect = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        (ReadOnlyMemory<byte> initialPacket, ReadOnlyMemory<byte> handshakePacket) =
            SplitCoalescedInitialAndHandshakeProbeDatagram(coalescedProbeEffect);

        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(initialPacket.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(handshakePacket.Span));

        Assert.True(coordinator.TryOpenHandshakePacket(
            handshakePacket.Span,
            handshakeMaterial,
            out byte[] openedHandshakePacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHandshakePacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame cryptoFrame,
            out _));
        Assert.Equal(0UL, cryptoFrame.Offset);
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(cryptoFrame.CryptoData));
        Assert.True(QuicPacketParser.TryParseLongHeader(initialPacket.Span, out QuicLongHeaderPacket initialLongHeader));
        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeLongHeader));
        Assert.Equal(
            Convert.ToHexString(handshakeDestinationConnectionId),
            Convert.ToHexString(initialLongHeader.DestinationConnectionId.ToArray()));
        Assert.Equal(
            Convert.ToHexString(handshakeDestinationConnectionId),
            Convert.ToHexString(handshakeLongHeader.DestinationConnectionId.ToArray()));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HandleRecoveryTimerExpired_DoesNotEmitApplicationDataProbesBeforeHandshakeConfirmation()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-151453678-client-chrome
        //   live-server-qlog\74ee1c872fe7b3f5.sqlog:
        //     quic-go buffered the client's 1-RTT request packets at 1274-1275ms because the client
        //     Handshake CRYPTO that carried Finished did not arrive until 6473ms. Emitting a 1-RTT PTO
        //     probe before HANDSHAKE_DONE confirms the handshake can therefore consume the peer's idle
        //     timeout budget without repairing the selected Handshake packet number space first.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            ApplicationPacketConnectionId,
            out QuicInitialPacketProtection initialPacketProtection));

        QuicHandshakeFlowCoordinator cryptoProbeCoordinator = new(
            ApplicationPacketConnectionId,
            ApplicationPacketSourceConnectionId);
        Assert.True(cryptoProbeCoordinator.TrySetHandshakeDestinationConnectionId(ApplicationPacketConnectionId));

        byte[] initialCrypto = CreateSequentialBytes(0x30, 16);
        Assert.True(cryptoProbeCoordinator.TryBuildProtectedInitialPacket(
            initialCrypto,
            0,
            initialPacketProtection,
            out ulong initialPacketNumber,
            out byte[] initialPacketBytes));
        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            initialPacketNumber,
            initialPacketBytes,
            sentAtMicros: 1,
            QuicTlsEncryptionLevel.Initial);

        Assert.True(runtime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial));
        byte[] handshakeCrypto = CreateSequentialBytes(0x40, 16);
        Assert.True(cryptoProbeCoordinator.TryBuildProtectedHandshakePacket(
            handshakeCrypto,
            0,
            handshakeMaterial,
            out ulong handshakePacketNumber,
            out byte[] handshakePacketBytes));
        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Handshake,
            handshakePacketNumber,
            handshakePacketBytes,
            sentAtMicros: 2,
            QuicTlsEncryptionLevel.Handshake);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[1400]),
            nowTicks: 9).StateChanged);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] requestPayload = CreateSequentialBytes(0xC0, 24);
        await stream.WriteAsync(requestPayload, 0, requestPayload.Length);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect requestEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packet.PacketBytes.Span.SequenceEqual(requestEffect.Datagram.Span));

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);
        outboundEffects.Clear();

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] sendEffects = timerResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.Single(sendEffects);

        QuicConnectionSendDatagramEffect coalescedProbeEffect = Assert.Single(
            sendEffects,
            sendEffect => TrySplitCoalescedInitialAndHandshakeProbeDatagram(sendEffect, out _, out _));
        (ReadOnlyMemory<byte> initialPacket, ReadOnlyMemory<byte> handshakePacket) =
            SplitCoalescedInitialAndHandshakeProbeDatagram(coalescedProbeEffect);

        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(initialPacket.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(handshakePacket.Span));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HandleRecoveryTimerExpired_AfterHandshakeConfirmationKeepsCryptoSpaceProbesAheadOfApplicationRepairWhileCryptoPacketsRemainOutstanding()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-124332682-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt
        // The confirmed client opened stream 0, logged that it sent "GET /clean-blue-chef\r\n",
        // and still had outstanding Initial and Handshake packets in flight. Even after
        // HANDSHAKE_DONE, those older crypto packet-number spaces remain responsible for the next
        // PTO until their repair is exhausted; the timer must not leak a 1-RTT request repair into
        // the same probe event while those crypto probes are still pending.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            ApplicationPacketConnectionId,
            out QuicInitialPacketProtection initialPacketProtection));

        QuicHandshakeFlowCoordinator cryptoProbeCoordinator = new(
            ApplicationPacketConnectionId,
            ApplicationPacketSourceConnectionId);
        Assert.True(cryptoProbeCoordinator.TrySetHandshakeDestinationConnectionId(ApplicationPacketConnectionId));

        byte[] initialCrypto = CreateSequentialBytes(0x30, 16);
        Assert.True(cryptoProbeCoordinator.TryBuildProtectedInitialPacket(
            initialCrypto,
            0,
            initialPacketProtection,
            out ulong initialPacketNumber,
            out byte[] initialPacketBytes));
        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            initialPacketNumber,
            initialPacketBytes,
            sentAtMicros: 1,
            QuicTlsEncryptionLevel.Initial);

        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial();
        byte[] handshakeCrypto = CreateSequentialBytes(0x40, 16);
        Assert.True(cryptoProbeCoordinator.TryBuildProtectedHandshakePacket(
            handshakeCrypto,
            0,
            handshakeMaterial,
            out ulong handshakePacketNumber,
            out byte[] handshakePacketBytes));
        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Handshake,
            handshakePacketNumber,
            handshakePacketBytes,
            sentAtMicros: 2,
            QuicTlsEncryptionLevel.Handshake);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath.Value.Identity,
                new byte[1280]),
            nowTicks: 10).StateChanged);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /clean-blue-chef\r\n");
        await stream.WriteAsync(requestPayload, 0, requestPayload.Length);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect requestEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packet.PacketBytes.Span.SequenceEqual(requestEffect.Datagram.Span));

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);
        outboundEffects.Clear();

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] sendEffects = timerResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(sendEffects);
        Assert.Contains(
            sendEffects,
            sendEffect => QuicPacketParser.TryParseLongHeader(sendEffect.Datagram.Span, out _));
        Assert.DoesNotContain(
            sendEffects,
            sendEffect => TryOpenSingleStreamFrame(runtime, sendEffect.Datagram, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HandleRecoveryTimerExpired_PrefersTheOutstandingApplicationPacketThatCarriesMissingStreamBytesBeforeAFinOnlyClose()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\20260421-multiconnect-regression\
        //   trace_node_left.pcap: client sent a zero-length stream-open marker, then an 87-byte request packet,
        //   then a FIN-only packet that closed the stream at offset 30.
        //   trace_node_right.pcap and server.log: only the FIN-only packet reached quic-go, so repeating it could
        //   not repair the missing request bytes.
        //   When a PTO probe must choose between data-bearing stream repair and a zero-byte FIN-only close,
        //   prefer the packet that still carries the missing bytes.
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-144036777-client-chrome\
        //   live-server-qlog\f532400d4e627fb6.sqlog: quic-go later observed the request bytes without FIN on the
        //   same HTTP/0.9 stream. The second same-space PTO probe therefore needs to repair the remaining FIN-only
        //   close instead of retransmitting the first request probe again.
        //   This runs from a handshake-confirmed client fixture because RFC 9002 forbids Application Data
        //   PTO before the client receives HANDSHAKE_DONE.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /abundant-endless-ocelot\r\n");
        byte[] requestFrame = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: 0,
            requestPayload,
            offset: 0);
        byte[] finishFrame = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0,
            streamData: [],
            offset: (ulong)requestPayload.Length);

        Assert.True(runtime.HandshakeConfirmed);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        byte[] requestPacketBytes = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            packetNumberBytes: [0x01],
            requestFrame,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 1);
        byte[] finishPacketBytes = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            packetNumberBytes: [0x02],
            finishFrame,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 1);
        Assert.True(TryOpenSingleStreamFrame(runtime, requestPacketBytes, out QuicStreamFrame parsedRequestFrame, out _));
        Assert.False(parsedRequestFrame.IsFin);
        Assert.Equal((ulong)requestPayload.Length, parsedRequestFrame.Offset + (ulong)parsedRequestFrame.StreamDataLength);
        Assert.True(TryOpenSingleStreamFrame(runtime, finishPacketBytes, out QuicStreamFrame parsedFinishFrame, out _));
        Assert.True(parsedFinishFrame.IsFin);
        Assert.Equal((ulong)requestPayload.Length, parsedFinishFrame.Offset + (ulong)parsedFinishFrame.StreamDataLength);

        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            requestPacketBytes,
            sentAtMicros: 1,
            QuicTlsEncryptionLevel.OneRtt,
            streamIds: [0UL]);
        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            finishPacketBytes,
            sentAtMicros: 2,
            QuicTlsEncryptionLevel.OneRtt,
            streamIds: [0UL]);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[1280]),
            nowTicks: 9).StateChanged);

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] applicationProbeEffects = timerResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(applicationProbeEffects);
        int requestProbeIndex = Array.FindIndex(
            applicationProbeEffects,
            effect => TryOpenSingleStreamFrame(runtime, effect.Datagram, out QuicStreamFrame frame, out _)
                && frame.StreamId.Value == 0UL
                && frame.Offset == 0UL
                && !frame.IsFin
                && frame.StreamData.SequenceEqual(requestPayload));
        Assert.True(requestProbeIndex >= 0, "Expected PTO to rebuild the data-bearing request packet.");
        int finishProbeIndex = Array.FindIndex(
            applicationProbeEffects,
            effect => TryOpenSingleStreamFrame(runtime, effect.Datagram, out QuicStreamFrame frame, out _)
                && frame.StreamId.Value == 0UL
                && frame.Offset == (ulong)requestPayload.Length
                && frame.IsFin
                && frame.StreamDataLength == 0);
        Assert.True(
            finishProbeIndex >= 0,
            $"Expected PTO to use its second same-space probe opportunity to rebuild the FIN-only close packet, but sent {applicationProbeEffects.Length} application probe datagram(s).");
        Assert.True(
            requestProbeIndex < finishProbeIndex,
            $"Expected the data-bearing request probe to precede the FIN-only close probe, but request probe index was {requestProbeIndex} and close probe index was {finishProbeIndex}.");

        ulong requestProbePacketNumber = QuicS12P3ApplicationRecoveryTestSupport.ReadApplicationPacketNumber(
            runtime,
            applicationProbeEffects[requestProbeIndex].Datagram,
            out QuicStreamFrame probeFrame,
            out bool requestKeyPhase);
        ulong finishProbePacketNumber = QuicS12P3ApplicationRecoveryTestSupport.ReadApplicationPacketNumber(
            runtime,
            applicationProbeEffects[finishProbeIndex].Datagram,
            out QuicStreamFrame finishProbeFrame,
            out bool finishKeyPhase);

        Assert.False(requestKeyPhase);
        Assert.Equal(0UL, probeFrame.StreamId.Value);
        Assert.Equal(0UL, probeFrame.Offset);
        Assert.False(probeFrame.IsFin);
        Assert.True(probeFrame.StreamData.SequenceEqual(requestPayload));
        Assert.False(finishKeyPhase);
        Assert.Equal(0UL, finishProbeFrame.StreamId.Value);
        Assert.Equal((ulong)requestPayload.Length, finishProbeFrame.Offset);
        Assert.True(finishProbeFrame.IsFin);
        Assert.Equal(0, finishProbeFrame.StreamDataLength);
        Assert.True(requestProbePacketNumber > 2UL);
        Assert.True(finishProbePacketNumber > requestProbePacketNumber);
        Assert.False(applicationProbeEffects[requestProbeIndex].Datagram.Span.SequenceEqual(requestPacketBytes.AsSpan()));
        Assert.False(applicationProbeEffects[finishProbeIndex].Datagram.Span.SequenceEqual(finishPacketBytes.AsSpan()));
        Assert.Contains(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.ProbePacket
                && entry.Key.PacketNumber == requestProbePacketNumber
                && entry.Value.PacketBytes.Span.SequenceEqual(applicationProbeEffects[requestProbeIndex].Datagram.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.ProbePacket
                && entry.Key.PacketNumber == finishProbePacketNumber
                && entry.Value.PacketBytes.Span.SequenceEqual(applicationProbeEffects[finishProbeIndex].Datagram.Span));
    }

    private static QuicConnectionSendDatagramEffect FindInitialProbeEffect(
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (QuicPacketParser.TryParseLongHeader(sendEffect.Datagram.Span, out QuicLongHeaderPacket packet)
                && packet.LongPacketTypeBits == QuicLongPacketTypeBits.Initial)
            {
                return sendEffect;
            }
        }

        Assert.Fail("No Initial PTO probe datagram was emitted.");
        return default!;
    }

    private static QuicConnectionSendDatagramEffect FindHandshakeProbeEffect(
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial handshakeMaterial)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (coordinator.TryOpenHandshakePacket(
                sendEffect.Datagram.Span,
                handshakeMaterial,
                out _,
                out _,
                out _))
            {
                return sendEffect;
            }
        }

        Assert.Fail("No Handshake PTO probe datagram was emitted.");
        return default!;
    }

    private static QuicConnectionSendDatagramEffect FindHandshakeCryptoProbeEffect(
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial handshakeMaterial,
        byte[] expectedCrypto)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (!coordinator.TryOpenHandshakePacket(
                    sendEffect.Datagram.Span,
                    handshakeMaterial,
                    out byte[] openedPacket,
                    out int payloadOffset,
                    out int payloadLength))
            {
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(
                    openedPacket.AsSpan(payloadOffset, payloadLength),
                    out QuicCryptoFrame cryptoFrame,
                    out _))
            {
                continue;
            }

            if (cryptoFrame.Offset == 0UL
                && expectedCrypto.AsSpan().SequenceEqual(cryptoFrame.CryptoData))
            {
                return sendEffect;
            }
        }

        Assert.Fail("No Handshake PTO probe retransmitted the expected CRYPTO frame.");
        return default!;
    }

    private static (ReadOnlyMemory<byte> InitialPacket, ReadOnlyMemory<byte> HandshakePacket)
        SplitCoalescedInitialAndHandshakeProbeDatagram(QuicConnectionSendDatagramEffect sendEffect)
    {
        Assert.True(TrySplitCoalescedInitialAndHandshakeProbeDatagram(sendEffect, out ReadOnlyMemory<byte> initialPacket, out ReadOnlyMemory<byte> handshakePacket));
        return (initialPacket, handshakePacket);
    }

    private static bool TrySplitCoalescedInitialAndHandshakeProbeDatagram(
        QuicConnectionSendDatagramEffect sendEffect,
        out ReadOnlyMemory<byte> initialPacket,
        out ReadOnlyMemory<byte> handshakePacket)
    {
        initialPacket = default;
        handshakePacket = default;

        if (!QuicPacketParser.TryGetPacketLength(sendEffect.Datagram.Span, out int initialPacketLength))
        {
            return false;
        }

        initialPacket = sendEffect.Datagram[..initialPacketLength];
        if (!QuicPacketParser.TryParseLongHeader(initialPacket.Span, out QuicLongHeaderPacket initialLongHeader)
            || initialLongHeader.LongPacketTypeBits != QuicLongPacketTypeBits.Initial)
        {
            initialPacket = default;
            return false;
        }

        ReadOnlyMemory<byte> handshakeRemainder = sendEffect.Datagram[initialPacketLength..];
        if (!QuicPacketParser.TryGetPacketLength(handshakeRemainder.Span, out int handshakePacketLength))
        {
            initialPacket = default;
            return false;
        }

        handshakePacket = handshakeRemainder[..handshakePacketLength];
        if (handshakePacketLength != handshakeRemainder.Length
            || !QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeLongHeader)
            || handshakeLongHeader.LongPacketTypeBits != QuicLongPacketTypeBits.Handshake)
        {
            initialPacket = default;
            handshakePacket = default;
            return false;
        }

        return true;
    }

    private static QuicConnectionSendDatagramEffect FindApplicationStreamProbeEffect(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        ulong expectedStreamId,
        ulong finalSize,
        out bool keyPhase)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (!TryOpenSingleStreamFrame(runtime, sendEffect.Datagram, out QuicStreamFrame frame, out keyPhase))
            {
                continue;
            }

            if (frame.StreamId.Value == expectedStreamId
                && frame.IsFin
                && frame.Offset + (ulong)frame.StreamDataLength == finalSize)
            {
                return sendEffect;
            }
        }

        keyPhase = false;
        Assert.Fail("No application PTO probe closed the expected stream.");
        return default!;
    }

    private static QuicStreamFrame OpenSingleStreamFrame(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        out bool keyPhase)
    {
        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out keyPhase));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame frame));
        return frame;
    }

    private static bool TryOpenSingleStreamFrame(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        out QuicStreamFrame frame,
        out bool keyPhase)
    {
        frame = default;
        keyPhase = false;

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId.ToArray());
        if (!coordinator.TryOpenProtectedApplicationDataPacket(
                datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out keyPhase))
        {
            return false;
        }

        return QuicStreamParser.TryParseStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out frame);
    }

    private static void SeedOutstandingRecoveryPacket(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        byte[] packetBytes,
        ulong sentAtMicros,
        QuicTlsEncryptionLevel packetProtectionLevel,
        ulong[]? streamIds = null)
    {
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            (ulong)packetBytes.Length,
            sentAtMicros,
            AckEliciting: true,
            AckOnlyPacket: false,
            ProbePacket: false,
            Retransmittable: true,
            PacketBytes: packetBytes,
            PacketProtectionLevel: packetProtectionLevel,
            StreamIds: streamIds));

        GetRecoveryController(runtime).RecordPacketSent(
            packetNumberSpace,
            packetNumber,
            sentAtMicros,
            isAckElicitingPacket: true,
            isProbePacket: false,
            packetProtectionLevel);
    }

    private static QuicRecoveryController GetRecoveryController(QuicConnectionRuntime runtime)
    {
        FieldInfo? recoveryControllerField = typeof(QuicConnectionRuntime).GetField(
            "recoveryController",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(recoveryControllerField);
        return Assert.IsType<QuicRecoveryController>(recoveryControllerField.GetValue(runtime));
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
