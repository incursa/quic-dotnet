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
        Assert.Equal(2, sendEffects.Length);
        Assert.All(sendEffects, sendEffect =>
            Assert.True(coordinator.TryOpenHandshakePacket(
                sendEffect.Datagram.Span,
                handshakeMaterial,
                out _,
                out _,
                out _)));

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            sendEffects,
            sendEffect => runtime.SendRuntime.SentPackets.Values.Any(
                packet => packet.ProbePacket
                    && packet.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span)));
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
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
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
    public void HandleRecoveryTimerExpired_AfterAnInitialOnlyPtoStillUsesTheNextProbeBudgetForHandshakeRepairOnceHandshakePacketsExist()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-085849660-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     connection 32/50 started on tuple 193.167.100.100:443|193.167.0.100:47878,
        //     the simulator later showed repeated 1200-byte client Initial retransmissions,
        //     and no client 79-byte Handshake repair ever reached the server on that tuple.
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt:
        //     quic-go received client Initial packets 3 and 4 for connection f3cbb6db380cebe1,
        //     but no later client Handshake packet before timing out.
        // Recreate the bounded recovery shape behind that preserved failure: the client already
        // spent one PTO entirely in the Initial space, then learned the peer Handshake flight.
        // The next PTO must still reserve the second probe datagram for Handshake repair instead
        // of emitting two more Initial retransmissions and starving the Handshake space.
        using QuicCapturedInteropReplayTestSupport.CapturedInteropHandshakeScenario scenario =
            QuicCapturedInteropReplayTestSupport.CreateDeterministicQuicGoClientHandshakeScenario();

        QuicConnectionRuntime runtime = scenario.ClientRuntime;

        long? firstRecoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(firstRecoveryDueTicks);
        ulong firstRecoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult firstPtoResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: firstRecoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                firstRecoveryGeneration),
            nowTicks: firstRecoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] firstPtoSendEffects = firstPtoResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.Equal(2, firstPtoSendEffects.Length);
        Assert.All(firstPtoSendEffects, sendEffect =>
        {
            Assert.True(QuicPacketParser.TryParseLongHeader(sendEffect.Datagram.Span, out QuicLongHeaderPacket packet));
            Assert.Equal(QuicLongPacketTypeBits.Initial, packet.LongPacketTypeBits);
        });

        QuicConnectionTransitionResult initialResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: firstRecoveryDueTicks.Value + 1,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerInitialPacket),
            nowTicks: firstRecoveryDueTicks.Value + 1);

        Assert.True(initialResult.StateChanged);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial));
        QuicHandshakeFlowCoordinator coordinator = new();

        QuicConnectionTransitionResult handshakeResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: firstRecoveryDueTicks.Value + 2,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerHandshakePacket),
            nowTicks: firstRecoveryDueTicks.Value + 2);

        Assert.True(handshakeResult.StateChanged);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.Contains(
            handshakeResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            sendEffect => coordinator.TryOpenHandshakePacket(
                sendEffect.Datagram.Span,
                handshakeMaterial,
                out _,
                out _,
                out _));

        long? secondRecoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(secondRecoveryDueTicks);
        ulong secondRecoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult secondPtoResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: secondRecoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                secondRecoveryGeneration),
            nowTicks: secondRecoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect[] secondPtoSendEffects = secondPtoResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.Equal(2, secondPtoSendEffects.Length);
        Assert.Contains(
            secondPtoSendEffects,
            sendEffect => coordinator.TryOpenHandshakePacket(
                sendEffect.Datagram.Span,
                handshakeMaterial,
                out _,
                out _,
                out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HandleRecoveryTimerExpired_WhenInitialConsumesTheFirstProbeDatagram_CoalescesHandshakeAndApplicationDataOnTheSecondProbeDatagram()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-210708681-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     multiconnect connection 1/50 opened the request stream and sent "GET /clean-merry-floppy\r\n".
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt:
        //     quic-go processed a retransmitted client Initial, then buffered 1-RTT packets (537, 82, and 57 bytes)
        //     without receiving a timely Handshake repair before timeout.
        // The live path still held the active-path maximum datagram size at the RFC minimum, so the
        // first PTO datagram could only carry the Initial retransmission. The remaining probe
        // datagram still needs to carry the Handshake repair together with the 1-RTT request repair
        // when that smaller pair fits within the path limit.
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
        ulong constrainedMaximumDatagramSizeBytes = (ulong)initialPacketBytes.Length;
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(constrainedMaximumDatagramSizeBytes));
        Assert.Equal(
            constrainedMaximumDatagramSizeBytes,
            runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
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
                new byte[(int)constrainedMaximumDatagramSizeBytes]),
            nowTicks: 9).StateChanged);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /clean-merry-floppy\r\n");
        await stream.WriteAsync(requestPayload, 0, requestPayload.Length);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect requestEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(
            initialPacketBytes.Length + handshakePacketBytes.Length
                > (long)constrainedMaximumDatagramSizeBytes);
        Assert.True(
            requestEffect.Datagram.Length + handshakePacketBytes.Length
                <= (long)constrainedMaximumDatagramSizeBytes);

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
        Assert.Equal(2, sendEffects.Length);

        QuicConnectionSendDatagramEffect initialProbeEffect = FindInitialProbeEffect(sendEffects);
        Assert.False(TrySplitCoalescedInitialAndHandshakeProbeDatagram(initialProbeEffect, out _, out _));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(initialProbeEffect.Datagram.Span));

        QuicConnectionSendDatagramEffect remainingProbeEffect = Assert.Single(
            sendEffects,
            sendEffect => !sendEffect.Datagram.Span.SequenceEqual(initialProbeEffect.Datagram.Span));
        (ReadOnlyMemory<byte> handshakeRepairPacket, ReadOnlyMemory<byte> applicationRepairPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(remainingProbeEffect);

        Assert.True(cryptoProbeCoordinator.TryOpenHandshakePacket(
            handshakeRepairPacket.Span,
            handshakeMaterial,
            out byte[] openedHandshakeRepairPacket,
            out int handshakePayloadOffset,
            out int handshakePayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHandshakeRepairPacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
            out QuicCryptoFrame handshakeProbeFrame,
            out _));
        Assert.Equal(0UL, handshakeProbeFrame.Offset);
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(handshakeProbeFrame.CryptoData));
        Assert.True(
            TryOpenSingleStreamFrame(runtime, applicationRepairPacket, out QuicStreamFrame applicationProbeFrame, out _));
        Assert.Equal(0UL, applicationProbeFrame.StreamId.Value);
        Assert.Equal(0UL, applicationProbeFrame.Offset);
        Assert.True(applicationProbeFrame.StreamData.SequenceEqual(requestPayload));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(handshakeRepairPacket.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(applicationRepairPacket.Span));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HandleRecoveryTimerExpired_WhenHandshakeConsumesTheFirstProbeDatagram_CoalescesHandshakeAndApplicationDataOnTheSecondProbeDatagram()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-215519155-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     multiconnect connection 10/50 opened the request stream and sent "GET /roasting-surprised-elephant\r\n",
        //     then the simulator forwarded 1-RTT packets while dropping repeated 79-byte Handshake repairs.
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt:
        //     quic-go processed the client's Initial packets, queued later-decryption 1-RTT packets
        //     (537, 57, and 57 bytes), and timed out before any timely client Handshake repair arrived.
        // The remaining PTO datagram still needs to carry a Handshake repair together with the 1-RTT
        // request repair even when the selected crypto space is Handshake and Initial remains in flight.
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

        Assert.True(runtime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial));
        byte[] handshakeCrypto = CreateSequentialBytes(0x40, 16);
        Assert.True(cryptoProbeCoordinator.TryBuildProtectedHandshakePacket(
            handshakeCrypto,
            0,
            handshakeMaterial,
            out ulong handshakePacketNumber,
            out byte[] handshakePacketBytes));

        ulong constrainedMaximumDatagramSizeBytes = (ulong)initialPacketBytes.Length;
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(constrainedMaximumDatagramSizeBytes));
        Assert.Equal(
            constrainedMaximumDatagramSizeBytes,
            runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);

        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Handshake,
            handshakePacketNumber,
            handshakePacketBytes,
            sentAtMicros: 1,
            QuicTlsEncryptionLevel.Handshake);
        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            initialPacketNumber,
            initialPacketBytes,
            sentAtMicros: 2,
            QuicTlsEncryptionLevel.Initial);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[(int)constrainedMaximumDatagramSizeBytes]),
            nowTicks: 9).StateChanged);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /roasting-surprised-elephant\r\n");
        await stream.WriteAsync(requestPayload, 0, requestPayload.Length);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect requestEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(
            initialPacketBytes.Length + handshakePacketBytes.Length
                > (long)constrainedMaximumDatagramSizeBytes);
        Assert.True(
            requestEffect.Datagram.Length + handshakePacketBytes.Length
                <= (long)constrainedMaximumDatagramSizeBytes);

        List<QuicConnectionEffect>? firstProbeEffects = [];
        Assert.True(InvokeTrySendRecoveryProbeDatagram(
            runtime,
            QuicPacketNumberSpace.Handshake,
            nowTicks: 10,
            ref firstProbeEffects));
        QuicConnectionSendDatagramEffect handshakeProbeEffect = Assert.Single(
            firstProbeEffects!.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(QuicPacketParser.TryGetPacketLength(
            handshakeProbeEffect.Datagram.Span,
            out int handshakeProbePacketLength));
        ReadOnlyMemory<byte> handshakeProbePacket = handshakeProbeEffect.Datagram[..handshakeProbePacketLength];

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakeProbePacket.Span, out QuicLongHeaderPacket handshakeLongHeader));
        Assert.Equal(QuicLongPacketTypeBits.Handshake, handshakeLongHeader.LongPacketTypeBits);
        Assert.True(cryptoProbeCoordinator.TryOpenHandshakePacket(
            handshakeProbePacket.Span,
            handshakeMaterial,
            out byte[] openedHandshakePacket,
            out int handshakePayloadOffset,
            out int handshakePayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
            out QuicCryptoFrame handshakeProbeFrame,
            out _));
        Assert.Equal(0UL, handshakeProbeFrame.Offset);
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(handshakeProbeFrame.CryptoData));

        List<QuicConnectionEffect>? remainingProbeEffects = [];
        Assert.True(InvokeTrySendAdditionalRecoveryProbeDatagram(
            runtime,
            QuicPacketNumberSpace.Handshake,
            QuicPacketNumberSpace.Initial,
            QuicPacketNumberSpace.ApplicationData,
            nowTicks: 11,
            initialAndHandshakeAlreadyCoalesced: false,
            ref remainingProbeEffects));
        QuicConnectionSendDatagramEffect remainingProbeEffect = Assert.Single(
            remainingProbeEffects!.OfType<QuicConnectionSendDatagramEffect>());
        (ReadOnlyMemory<byte> handshakeRepairPacket, ReadOnlyMemory<byte> applicationRepairPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(remainingProbeEffect);

        Assert.True(cryptoProbeCoordinator.TryOpenHandshakePacket(
            handshakeRepairPacket.Span,
            handshakeMaterial,
            out byte[] openedHandshakeRepairPacket,
            out int handshakeRepairPayloadOffset,
            out int handshakeRepairPayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHandshakeRepairPacket.AsSpan(handshakeRepairPayloadOffset, handshakeRepairPayloadLength),
            out QuicCryptoFrame handshakeRepairFrame,
            out _));
        Assert.Equal(0UL, handshakeRepairFrame.Offset);
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(handshakeRepairFrame.CryptoData));
        Assert.True(
            TryOpenSingleStreamFrame(runtime, applicationRepairPacket, out QuicStreamFrame applicationProbeFrame, out _));
        Assert.Equal(0UL, applicationProbeFrame.StreamId.Value);
        Assert.Equal(0UL, applicationProbeFrame.Offset);
        Assert.True(applicationProbeFrame.StreamData.SequenceEqual(requestPayload));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(handshakeRepairPacket.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(applicationRepairPacket.Span));
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
    public async Task HandleRecoveryTimerExpired_CoalescesHandshakeAndApplicationDataOnTheRemainingProbeDatagramBeforeHandshakeConfirmation()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-205002011-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     multiconnect connection 41/50 opened the request stream and sent "GET /clean-envious-vinyl\r\n".
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt:
        //     quic-go queued three later-decryption 1-RTT packets (537, 57, and 83 bytes),
        //     then timed out before a usable Handshake repair arrived.
        // The live failure proves that spending the remaining PTO datagram on 1-RTT alone is not
        // enough on this path. When Initial+Handshake already consumed the first PTO datagram and
        // the path can still carry more, keep a Handshake repair attached to the remaining 1-RTT
        // repair so the peer can unlock the buffered request bytes in the same datagram flight.
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
        Assert.Equal(2, sendEffects.Length);

        QuicConnectionSendDatagramEffect coalescedProbeEffect = Assert.Single(
            sendEffects,
            sendEffect => TrySplitCoalescedInitialAndHandshakeProbeDatagram(sendEffect, out _, out _));
        (ReadOnlyMemory<byte> initialPacket, ReadOnlyMemory<byte> handshakePacket) =
            SplitCoalescedInitialAndHandshakeProbeDatagram(coalescedProbeEffect);

        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(initialPacket.Span));

        QuicConnectionSendDatagramEffect remainingProbeEffect = Assert.Single(
            sendEffects,
            sendEffect => !sendEffect.Datagram.Span.SequenceEqual(coalescedProbeEffect.Datagram.Span));
        (ReadOnlyMemory<byte> handshakeRepairPacket, ReadOnlyMemory<byte> applicationRepairPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(remainingProbeEffect);

        Assert.True(cryptoProbeCoordinator.TryOpenHandshakePacket(
            handshakeRepairPacket.Span,
            handshakeMaterial,
            out byte[] openedHandshakeRepairPacket,
            out int handshakePayloadOffset,
            out int handshakePayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHandshakeRepairPacket.AsSpan(handshakePayloadOffset, handshakePayloadLength),
            out QuicCryptoFrame handshakeProbeFrame,
            out _));
        Assert.Equal(0UL, handshakeProbeFrame.Offset);
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(handshakeProbeFrame.CryptoData));
        Assert.True(
            TryOpenSingleStreamFrame(runtime, applicationRepairPacket, out QuicStreamFrame applicationProbeFrame, out _));
        Assert.Equal(0UL, applicationProbeFrame.StreamId.Value);
        Assert.Equal(0UL, applicationProbeFrame.Offset);
        Assert.True(applicationProbeFrame.StreamData.SequenceEqual(requestPayload));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(handshakeRepairPacket.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(applicationRepairPacket.Span));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HandleRecoveryTimerExpired_RebuildsTheApplicationRepairUnderTheLatestPeerConnectionIdBeforeHandshakeConfirmation()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\20260421-multiconnect-conn9-live\
        //   server-log.txt lines 1240-1366:
        //     connection c62a05b3c913eeef issued NEW_CONNECTION_ID a19b5b6e,
        //     then quic-go later received only packet 1 with a zero-length STREAM open marker on that new CID,
        //     dropped repeated Initial+Handshake probes after key discard,
        //     and timed out without ever receiving the request-bearing STREAM repair.
        // Re-enact the peer CID update before PTO and require the remaining Application Data repair
        // datagram to rebuild the request bytes under the latest destination CID instead of depending
        // on reopening the old protected packet with its earlier short-header connection ID.
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

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /conn9-cid-drift\r\n");
        await stream.WriteAsync(requestPayload, 0, requestPayload.Length);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect requestEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(
            TryOpenSingleStreamFrame(runtime, requestEffect.Datagram, out QuicStreamFrame originalRequestFrame, out _));
        Assert.Equal(0UL, originalRequestFrame.StreamId.Value);
        Assert.Equal(0UL, originalRequestFrame.Offset);
        Assert.True(originalRequestFrame.StreamData.SequenceEqual(requestPayload));

        byte[] rotatedPeerDestinationConnectionId = [0xA1, 0x9B, 0x5B, 0x6E];
        byte[] statelessResetToken = CreateSequentialBytes(0xD0, QuicStatelessReset.StatelessResetTokenLength);
        Assert.True(ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1,
            retirePriorTo: 0,
            connectionId: rotatedPeerDestinationConnectionId,
            statelessResetToken,
            observedAtTicks: 10).StateChanged);
        Assert.Equal(
            Convert.ToHexString(rotatedPeerDestinationConnectionId),
            Convert.ToHexString(runtime.CurrentPeerDestinationConnectionId.ToArray()));

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
        Assert.Equal(2, sendEffects.Length);

        QuicConnectionSendDatagramEffect coalescedProbeEffect = Assert.Single(
            sendEffects,
            sendEffect => TrySplitCoalescedInitialAndHandshakeProbeDatagram(sendEffect, out _, out _));
        QuicConnectionSendDatagramEffect remainingProbeEffect = Assert.Single(
            sendEffects,
            sendEffect => !sendEffect.Datagram.Span.SequenceEqual(coalescedProbeEffect.Datagram.Span));
        (ReadOnlyMemory<byte> handshakeRepairPacket, ReadOnlyMemory<byte> applicationRepairPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(remainingProbeEffect);

        Assert.True(
            TryOpenSingleStreamFrame(runtime, applicationRepairPacket, out QuicStreamFrame applicationProbeFrame, out _));
        Assert.Equal(0UL, applicationProbeFrame.StreamId.Value);
        Assert.Equal(0UL, applicationProbeFrame.Offset);
        Assert.True(applicationProbeFrame.StreamData.SequenceEqual(requestPayload));
        Assert.False(applicationRepairPacket.Span.SequenceEqual(requestEffect.Datagram.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(handshakeRepairPacket.Span));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(applicationRepairPacket.Span));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HandleRecoveryTimerExpired_AfterHandshakeConfirmationKeepsCryptoSpaceProbesAheadOfApplicationRepairWhileRepairingApplicationData()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-124332682-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt
        // The confirmed client opened stream 0, logged that it sent "GET /clean-blue-chef\r\n",
        // and still had outstanding Initial and Handshake packets in flight. Even after
        // HANDSHAKE_DONE, those older crypto packet-number spaces remain responsible for the next
        // PTO. REQ-QUIC-RFC9002-S6P2P4-0004 still expects the sender to use the remaining probe
        // budget for other spaces with in-flight data, so the probe event must keep the crypto
        // repair present while also repairing the 1-RTT request stream.
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
        int applicationProbeIndex = Array.FindIndex(
            sendEffects,
            sendEffect => TryExtractApplicationRepairPacket(
                    runtime,
                    sendEffect,
                    out _,
                    out QuicStreamFrame frame)
                && frame.StreamId.Value == 0UL
                && frame.Offset == 0UL
                && frame.StreamData.SequenceEqual(requestPayload));
        Assert.True(applicationProbeIndex >= 0, "Expected the PTO event to repair the in-flight 1-RTT request stream.");

        ReadOnlyMemory<byte> applicationRepairPacket;
        Assert.True(TryExtractApplicationRepairPacket(
            runtime,
            sendEffects[applicationProbeIndex],
            out applicationRepairPacket,
            out _));

        if (!TrySplitCoalescedHandshakeAndApplicationProbeDatagram(
                sendEffects[applicationProbeIndex],
                out _,
                out _))
        {
            int cryptoProbeIndex = Array.FindIndex(
                sendEffects,
                sendEffect => QuicPacketParser.TryParseLongHeader(sendEffect.Datagram.Span, out _));
            Assert.True(cryptoProbeIndex >= 0, "Expected a crypto-space PTO probe datagram.");
            Assert.True(
                cryptoProbeIndex < applicationProbeIndex,
                $"Expected the crypto-space PTO probe to precede the application repair probe, but cryptoProbeIndex was {cryptoProbeIndex} and applicationProbeIndex was {applicationProbeIndex}.");
        }

        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(applicationRepairPacket.Span));
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

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySendRecoveryProbeDatagram_PromotesLaterInitialCryptoRangeWhenPeerOnlyHasTheFirstRange()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-202551462-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt:
        //     connection 22e4aaf88b64abc3de276946447f54aa repeatedly received server Initial
        //     CRYPTO offset 0 length 56 and queued Handshake packets for later decryption.
        //   runner-logs\nginx_quic-go\handshakeloss\server\qlog\server-multiconnect-9b7c09063f6f44a48ff45111caa9a840.qlog:
        //     the server stayed in handshake_started on the 16th connection after Initial loss.
        // A PTO promotion must repair the furthest Initial CRYPTO range instead of repeatedly
        // choosing the earliest range the peer already received.
        using QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        Assert.True(runtime.TryConfigureInitialPacketProtection(
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection initialPacketProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        byte[] firstCryptoRange = CreateSequentialBytes(0x40, 56);
        byte[] laterCryptoRange = CreateSequentialBytes(0x80, 123);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            firstCryptoRange,
            0,
            initialPacketProtection,
            out ulong firstPacketNumber,
            out byte[] firstPacketBytes));
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            laterCryptoRange,
            (ulong)firstCryptoRange.Length,
            initialPacketProtection,
            out ulong laterPacketNumber,
            out byte[] laterPacketBytes));

        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            firstPacketNumber,
            firstPacketBytes,
            sentAtMicros: 1,
            QuicTlsEncryptionLevel.Initial);
        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            laterPacketNumber,
            laterPacketBytes,
            sentAtMicros: 2,
            QuicTlsEncryptionLevel.Initial);

        List<QuicConnectionEffect>? effects = null;
        Assert.True(InvokeTrySendRecoveryProbeDatagram(
            runtime,
            QuicPacketNumberSpace.Initial,
            nowTicks: 20,
            ref effects));

        Assert.NotNull(effects);
        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(coordinator.TryOpenOutboundInitialPacket(
            sendEffect.Datagram.Span,
            initialPacketProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame cryptoFrame,
            out _));
        Assert.Equal((ulong)firstCryptoRange.Length, cryptoFrame.Offset);
        Assert.True(laterCryptoRange.AsSpan().SequenceEqual(cryptoFrame.CryptoData));
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            packet => packet.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && packet.ProbePacket
                && packet.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySendRecoveryProbeDatagram_SendsUnsentInitialCryptoBeforeQueuedEarlyRetransmission()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-204247913-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt:
        //     connection 72da15523d43f85f repeatedly received server Initial CRYPTO offset 0
        //     and timed out before receiving the later Initial range needed for Handshake keys.
        //   runner-logs\nginx_quic-go\handshakeloss\server\qlog\server-multiconnect-de19c40d8f3d4842a4be5932a722b927.qlog:
        //     the server had received repeated client Initial probes while staying in handshake_started.
        // Preserve unsent CRYPTO progress ahead of stale retransmission work when PTO repairs Initial.
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateClientRuntime();
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection initialPacketProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        byte[] laterCryptoRange = CreateSequentialBytes(0x90, 123);

        QuicConnectionTransitionResult firstSendResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 1,
                LocalTransportParameters: QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(
                    QuicS17P2P5P2TestSupport.InitialSourceConnectionId)),
            nowTicks: 1);
        QuicConnectionSendDatagramEffect firstSendEffect = Assert.Single(
            firstSendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(coordinator.TryOpenOutboundInitialPacket(
            firstSendEffect.Datagram.Span,
            initialPacketProtection,
            out byte[] openedFirstPacket,
            out int firstPayloadOffset,
            out int firstPayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedFirstPacket.AsSpan(firstPayloadOffset, firstPayloadLength),
            out QuicCryptoFrame firstCryptoFrame,
            out _));
        Assert.Equal(0UL, firstCryptoFrame.Offset);
        ulong laterCryptoOffset = (ulong)firstCryptoFrame.CryptoData.Length;

        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 0,
            PayloadBytes: (ulong)firstSendEffect.Datagram.Length,
            SentAtMicros: 1,
            ProbePacket: false,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: firstSendEffect.Datagram,
            PacketProtectionLevel: QuicTlsEncryptionLevel.Initial));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.CryptoDataAvailable,
            QuicTlsEncryptionLevel.Initial,
            CryptoDataOffset: laterCryptoOffset,
            CryptoData: laterCryptoRange)));

        List<QuicConnectionEffect>? effects = null;
        Assert.True(InvokeTrySendRecoveryProbeDatagram(
            runtime,
            QuicPacketNumberSpace.Initial,
            nowTicks: 20,
            ref effects));

        Assert.NotNull(effects);
        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(coordinator.TryOpenOutboundInitialPacket(
            sendEffect.Datagram.Span,
            initialPacketProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame cryptoFrame,
            out _));
        Assert.Equal(laterCryptoOffset, cryptoFrame.Offset);
        Assert.True(laterCryptoRange.AsSpan().SequenceEqual(cryptoFrame.CryptoData));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDequeuePreferredProbeRetransmission_PrefersLaterInitialCryptoRangeWhenPtoMustRepairCrypto()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-202551462-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\qlog\22e4aaf88b64abc3de276946447f54aa.sqlog:
        //     the peer queued Handshake packets but did not install Handshake keys after seeing
        //     only the first server Initial CRYPTO range.
        // Keep queued Initial retransmission selection focused on CRYPTO stream progress.
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection initialPacketProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        byte[] firstCryptoRange = CreateSequentialBytes(0x20, 56);
        byte[] laterCryptoRange = CreateSequentialBytes(0x70, 123);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            firstCryptoRange,
            0,
            initialPacketProtection,
            out ulong firstPacketNumber,
            out byte[] firstPacketBytes));
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            laterCryptoRange,
            (ulong)firstCryptoRange.Length,
            initialPacketProtection,
            out ulong laterPacketNumber,
            out byte[] laterPacketBytes));

        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.Initial,
            firstPacketNumber,
            PayloadBytes: (ulong)firstPacketBytes.Length,
            SentAtMicros: 1,
            ProbePacket: false,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: firstPacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.Initial));
        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.Initial,
            laterPacketNumber,
            PayloadBytes: (ulong)laterPacketBytes.Length,
            SentAtMicros: 2,
            ProbePacket: false,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: laterPacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.Initial));

        Assert.True(TryDequeuePreferredProbeRetransmission(
            runtime,
            QuicPacketNumberSpace.Initial,
            out QuicConnectionRetransmissionPlan selectedRetransmission));
        Assert.Equal(laterPacketNumber, selectedRetransmission.PacketNumber);
        Assert.True(selectedRetransmission.PacketBytes.Span.SequenceEqual(laterPacketBytes));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(
            QuicPacketNumberSpace.Initial,
            out QuicConnectionRetransmissionPlan remainingRetransmission));
        Assert.Equal(firstPacketNumber, remainingRetransmission.PacketNumber);
        Assert.True(remainingRetransmission.PacketBytes.Span.SequenceEqual(firstPacketBytes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDequeuePreferredProbeRetransmission_PreservesInitialFifoWhenCryptoPriorityCannotBeRead()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        byte[] firstPacketBytes = [0xC0, 0x00, 0x01];
        byte[] secondPacketBytes = [0xC0, 0x00, 0x02];

        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 7,
            PayloadBytes: (ulong)firstPacketBytes.Length,
            SentAtMicros: 1,
            ProbePacket: false,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: firstPacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.Initial));
        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 8,
            PayloadBytes: (ulong)secondPacketBytes.Length,
            SentAtMicros: 2,
            ProbePacket: false,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: secondPacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.Initial));

        Assert.True(TryDequeuePreferredProbeRetransmission(
            runtime,
            QuicPacketNumberSpace.Initial,
            out QuicConnectionRetransmissionPlan selectedRetransmission));
        Assert.Equal(7UL, selectedRetransmission.PacketNumber);
        Assert.True(selectedRetransmission.PacketBytes.Span.SequenceEqual(firstPacketBytes));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDequeuePreferredProbeRetransmission_PrefersAnUnprobedFinOnlyCloseOverARequestPacketThatAlreadyServedAsAProbe()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-191124687-client-chrome\
        //   live docker logs server:
        //     packet 5 -> STREAM offset 0 length 26
        //     packets 8/10/11/14/15 -> repeated STREAM offset 0 length 26
        //   The server never observed the FIN-only close for stream 0 before timing out, so the
        //   request repair packet had already been spent as a PTO probe while the original close
        //   packet still needed its first repair attempt.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /bright-clean-floppy\r\n");
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

        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        byte[] requestProbePacketBytes = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            packetNumberBytes: [0x05],
            requestFrame,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 1);
        byte[] finishPacketBytes = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            packetNumberBytes: [0x02],
            finishFrame,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 1);

        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 5,
            PayloadBytes: (ulong)requestProbePacketBytes.Length,
            SentAtMicros: 5,
            ProbePacket: true,
            PacketBytes: requestProbePacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamIds: [0UL],
            PlaintextPayload: requestFrame));
        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: (ulong)finishPacketBytes.Length,
            SentAtMicros: 2,
            ProbePacket: false,
            PacketBytes: finishPacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamIds: [0UL],
            PlaintextPayload: finishFrame));

        Assert.True(TryDequeuePreferredProbeRetransmission(
            runtime,
            QuicPacketNumberSpace.ApplicationData,
            out QuicConnectionRetransmissionPlan selectedRetransmission));
        Assert.Equal(2UL, selectedRetransmission.PacketNumber);
        Assert.False(selectedRetransmission.ProbePacket);
        Assert.True(selectedRetransmission.PacketBytes.Span.SequenceEqual(finishPacketBytes));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
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

    private static (ReadOnlyMemory<byte> HandshakePacket, ReadOnlyMemory<byte> ApplicationPacket)
        SplitCoalescedHandshakeAndApplicationProbeDatagram(QuicConnectionSendDatagramEffect sendEffect)
    {
        Assert.True(TrySplitCoalescedHandshakeAndApplicationProbeDatagram(
            sendEffect,
            out ReadOnlyMemory<byte> handshakePacket,
            out ReadOnlyMemory<byte> applicationPacket));
        return (handshakePacket, applicationPacket);
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

    private static bool TrySplitCoalescedHandshakeAndApplicationProbeDatagram(
        QuicConnectionSendDatagramEffect sendEffect,
        out ReadOnlyMemory<byte> handshakePacket,
        out ReadOnlyMemory<byte> applicationPacket)
    {
        handshakePacket = default;
        applicationPacket = default;

        if (!QuicPacketParser.TryGetPacketLength(sendEffect.Datagram.Span, out int handshakePacketLength))
        {
            return false;
        }

        handshakePacket = sendEffect.Datagram[..handshakePacketLength];
        if (!QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeLongHeader)
            || handshakeLongHeader.LongPacketTypeBits != QuicLongPacketTypeBits.Handshake)
        {
            handshakePacket = default;
            return false;
        }

        ReadOnlyMemory<byte> applicationRemainder = sendEffect.Datagram[handshakePacketLength..];
        if (applicationRemainder.IsEmpty
            || !QuicPacketParser.TryGetPacketLength(applicationRemainder.Span, out int applicationPacketLength)
            || applicationPacketLength != applicationRemainder.Length)
        {
            handshakePacket = default;
            return false;
        }

        applicationPacket = applicationRemainder[..applicationPacketLength];
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

    private static bool TryExtractApplicationRepairPacket(
        QuicConnectionRuntime runtime,
        QuicConnectionSendDatagramEffect sendEffect,
        out ReadOnlyMemory<byte> applicationPacket,
        out QuicStreamFrame frame)
    {
        applicationPacket = default;
        frame = default;

        if (TryOpenSingleStreamFrame(runtime, sendEffect.Datagram, out frame, out _))
        {
            applicationPacket = sendEffect.Datagram;
            return true;
        }

        if (!TrySplitCoalescedHandshakeAndApplicationProbeDatagram(
                sendEffect,
                out _,
                out ReadOnlyMemory<byte> coalescedApplicationPacket)
            || !TryOpenSingleStreamFrame(runtime, coalescedApplicationPacket, out frame, out _))
        {
            return false;
        }

        applicationPacket = coalescedApplicationPacket;
        return true;
    }

    private static QuicConnectionTransitionResult ProcessNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            statelessResetToken));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        byte[] protectedPacket = QuicS17P2P3TestSupport.BuildExpectedOneRttPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            keyPhase: false);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
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

    private static bool TryDequeuePreferredProbeRetransmission(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        out QuicConnectionRetransmissionPlan retransmission)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TryDequeuePreferredProbeRetransmission",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        object?[] arguments =
        [
            packetNumberSpace,
            default(QuicConnectionRetransmissionPlan),
        ];

        bool dequeued = (bool)method.Invoke(runtime, arguments)!;
        retransmission = dequeued
            ? (QuicConnectionRetransmissionPlan)arguments[1]!
            : default;
        return dequeued;
    }

    private static bool InvokeTrySendRecoveryProbeDatagram(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TrySendRecoveryProbeDatagram",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        object?[] arguments =
        [
            packetNumberSpace,
            nowTicks,
            effects,
        ];

        bool sent = (bool)method.Invoke(runtime, arguments)!;
        effects = (List<QuicConnectionEffect>?)arguments[2];
        return sent;
    }

    private static bool InvokeTrySendAdditionalRecoveryProbeDatagram(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace firstPacketNumberSpace,
        QuicPacketNumberSpace secondPacketNumberSpace,
        QuicPacketNumberSpace thirdPacketNumberSpace,
        long nowTicks,
        bool initialAndHandshakeAlreadyCoalesced,
        ref List<QuicConnectionEffect>? effects)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TrySendAdditionalRecoveryProbeDatagram",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        object?[] arguments =
        [
            firstPacketNumberSpace,
            secondPacketNumberSpace,
            thirdPacketNumberSpace,
            nowTicks,
            initialAndHandshakeAlreadyCoalesced,
            effects,
        ];

        bool sent = (bool)method.Invoke(runtime, arguments)!;
        effects = (List<QuicConnectionEffect>?)arguments[5];
        return sent;
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
