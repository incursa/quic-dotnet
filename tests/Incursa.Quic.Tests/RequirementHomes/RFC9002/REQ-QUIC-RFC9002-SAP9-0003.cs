using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP9-0003">When the timer expires because of PTO rather than loss detection, the sender MUST send new data if available, otherwise retransmit old data, and if neither is available send a single PING frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP9-0003")]
public sealed class REQ_QUIC_RFC9002_SAP9_0003
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProbeContent_UsesNewApplicationDataWhenItIsAvailable()
    {
        byte[] streamData = [0x40, 0x41, 0x42];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x06,
            streamData,
            offset: 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.True(frame.HasLength);
        Assert.Equal(0UL, frame.Offset);
        Assert.Equal((ulong)streamData.Length, frame.Length);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(frame.FrameType));

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frame.FrameType,
            frame.StreamId.Value,
            frame.Offset,
            frame.StreamData,
            destination,
            out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryTimerExpired_ReplaysTheBootstrapInitialWhenNoNewClientCryptoIsAvailable()
    {
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

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
        Assert.NotEmpty(sendEffects);

        QuicConnectionSendDatagramEffect sendEffect = FindInitialProbeEffect(sendEffects);
        Assert.True(QuicPacketParser.TryParseLongHeader(sendEffect.Datagram.Span, out QuicLongHeaderPacket packet));
        Assert.Equal(QuicLongPacketTypeBits.Initial, packet.LongPacketTypeBits);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            sentPacket => sentPacket.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && sentPacket.ProbePacket
                && sentPacket.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
        Assert.Contains(timerResult.Effects, effect =>
            effect is QuicConnectionArmTimerEffect armEffect
            && armEffect.TimerKind == QuicConnectionTimerKind.Recovery);
        Assert.True(runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery) > recoveryGeneration);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryTimerExpired_RetransmitsOutstandingHandshakeCryptoWhenNoNewHandshakeDataIsAvailable()
    {
        QuicConnectionRuntime runtime = CreateEstablishingRuntimeWithActivePath();
        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial();
        QuicHandshakeFlowCoordinator coordinator = new();

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        byte[] handshakeCrypto = CreateSequentialPayload(0x20, 16);
        QuicConnectionTransitionResult firstSendResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: handshakeCrypto)),
            nowTicks: 4);

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
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(firstCryptoFrame.CryptoData));
        Assert.True(firstBytesConsumed > 0);
        Assert.Equal(0, runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes);

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
        Assert.NotEmpty(sendEffects);

        QuicConnectionSendDatagramEffect probeEffect = FindHandshakeCryptoProbeEffect(
            sendEffects,
            coordinator,
            handshakeMaterial,
            handshakeCrypto);
        Assert.True(coordinator.TryOpenHandshakePacket(
            probeEffect.Datagram.Span,
            handshakeMaterial,
            out byte[] openedProbePacket,
            out int probePayloadOffset,
            out int probePayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedProbePacket.AsSpan(probePayloadOffset, probePayloadLength),
            out QuicCryptoFrame probeCryptoFrame,
            out int probeBytesConsumed));
        Assert.Equal(0UL, probeCryptoFrame.Offset);
        Assert.True(handshakeCrypto.AsSpan().SequenceEqual(probeCryptoFrame.CryptoData));
        Assert.True(probeBytesConsumed > 0);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Values,
            sentPacket => sentPacket.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && sentPacket.ProbePacket);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RecoveryTimerExpired_RetransmitsLostApplicationDataBeforeFallingBackToPing()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = CreateSequentialPayload(0x40, 40);
        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect dataEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedDataPacket = FindTrackedPacket(runtime, dataEffect.Datagram);
        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            trackedDataPacket.Key.PacketNumberSpace,
            trackedDataPacket.Key.PacketNumber,
            handshakeConfirmed: true));

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
        Assert.DoesNotContain(sendEffects, sendEffect => IsPingOnlyPayload(runtime, sendEffect.Datagram));

        QuicConnectionSendDatagramEffect repairEffect = FindApplicationStreamProbeEffect(
            runtime,
            sendEffects,
            (ulong)stream.Id,
            payload,
            isFin: false,
            out bool keyPhase);
        QuicStreamFrame repairFrame = OpenSingleStreamFrame(runtime, repairEffect.Datagram, out keyPhase);

        Assert.False(keyPhase);
        Assert.Equal((ulong)stream.Id, repairFrame.StreamId.Value);
        Assert.Equal(0UL, repairFrame.Offset);
        Assert.False(repairFrame.IsFin);
        Assert.True(repairFrame.StreamData.SequenceEqual(payload));
        Assert.DoesNotContain(timerResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendEffect
            && IsPingOnlyPayload(runtime, sendEffect.Datagram));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task GapAckForLaterPacketsMakesPtoRetransmitTheMissingApplicationData()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedOpenPacket = FindTrackedPacket(runtime, openEffect.Datagram);
        outboundEffects.Clear();

        byte[] payload = CreateSequentialPayload(0x10, 40);
        await stream.WriteAsync(payload, 0, payload.Length);
        QuicConnectionSendDatagramEffect dataEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedDataPacket = FindTrackedPacket(runtime, dataEffect.Datagram);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect finEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedFinPacket = FindTrackedPacket(runtime, finEffect.Datagram);

        Assert.Equal(trackedOpenPacket.Key.PacketNumber + 1, trackedDataPacket.Key.PacketNumber);
        Assert.Equal(trackedDataPacket.Key.PacketNumber + 1, trackedFinPacket.Key.PacketNumber);

        byte[] protectedAckPacket = BuildProtectedAckPacket(
            runtime,
            largestAcknowledged: trackedFinPacket.Key.PacketNumber,
            firstAckRange: 0,
            additionalRanges:
            [
                new QuicAckRange(
                    gap: trackedFinPacket.Key.PacketNumber - trackedOpenPacket.Key.PacketNumber - 2,
                    ackRangeLength: 0,
                    smallestAcknowledged: trackedOpenPacket.Key.PacketNumber,
                    largestAcknowledged: trackedOpenPacket.Key.PacketNumber),
            ]);

        QuicConnectionTransitionResult ackResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 100,
                runtime.ActivePath!.Value.Identity,
                protectedAckPacket),
            nowTicks: 100);

        Assert.Empty(ackResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        for (int attempt = 0; attempt < 2; attempt++)
        {
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

            if (sendEffects.Length == 0)
            {
                continue;
            }

            Assert.DoesNotContain(sendEffects, sendEffect => IsPingOnlyPayload(runtime, sendEffect.Datagram));

            QuicConnectionSendDatagramEffect repairEffect = FindApplicationStreamProbeEffect(
                runtime,
                sendEffects,
                (ulong)stream.Id,
                payload,
                isFin: false,
                out bool keyPhase);
            QuicStreamFrame repairFrame = OpenSingleStreamFrame(runtime, repairEffect.Datagram, out keyPhase);

            Assert.False(keyPhase);
            Assert.Equal((ulong)stream.Id, repairFrame.StreamId.Value);
            Assert.Equal(0UL, repairFrame.Offset);
            Assert.False(repairFrame.IsFin);
            Assert.True(repairFrame.StreamData.SequenceEqual(payload));
            return;
        }

        Assert.Fail(
            $"No application-data repair probe was sent after the gap ACK. PendingRetransmissions={runtime.SendRuntime.PendingRetransmissionCount}, SentPackets={runtime.SendRuntime.SentPackets.Count}.");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AckingTheResponseBodyStillMakesPtoRetransmitTheOutstandingFinOnlyClose()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-143509531-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt:
        //     packet 57 carried STREAM stream_id=0 offset=0 length=1024,
        //     packet 58 remained missing, and the next server PTO emitted packet 59 with only PING.
        // The bounded regression is the application PTO content choice after the peer has already
        // acknowledged the body packet but not the later FIN-only close for the same stream.
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedOpenPacket = FindTrackedPacket(runtime, openEffect.Datagram);
        outboundEffects.Clear();

        byte[] payload = CreateSequentialPayload(0x20, 40);
        await stream.WriteAsync(payload, 0, payload.Length);
        QuicConnectionSendDatagramEffect dataEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedDataPacket = FindTrackedPacket(runtime, dataEffect.Datagram);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect finEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedFinPacket = FindTrackedPacket(runtime, finEffect.Datagram);

        Assert.Equal(trackedOpenPacket.Key.PacketNumber + 1, trackedDataPacket.Key.PacketNumber);
        Assert.Equal(trackedDataPacket.Key.PacketNumber + 1, trackedFinPacket.Key.PacketNumber);

        byte[] protectedAckPacket = BuildProtectedAckPacket(
            runtime,
            largestAcknowledged: trackedDataPacket.Key.PacketNumber,
            firstAckRange: trackedDataPacket.Key.PacketNumber - trackedOpenPacket.Key.PacketNumber,
            additionalRanges: []);

        QuicConnectionTransitionResult ackResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 100,
                runtime.ActivePath!.Value.Identity,
                protectedAckPacket),
            nowTicks: 100);

        Assert.Empty(ackResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedOpenPacket.Key.PacketNumber);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedDataPacket.Key.PacketNumber);
        Assert.Contains(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedFinPacket.Key.PacketNumber);

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
        string[] sendEffectDescriptions = sendEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        Assert.NotEmpty(sendEffects);
        Assert.DoesNotContain(sendEffects, sendEffect => IsPingOnlyPayload(runtime, sendEffect.Datagram));

        bool foundFinRepair = false;
        bool finRepairKeyPhase = false;
        QuicStreamFrame finRepairFrame = default;
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (!TryOpenSingleStreamFrame(runtime, sendEffect.Datagram, out QuicStreamFrame frame, out bool keyPhase))
            {
                continue;
            }

            if (frame.StreamId.Value == (ulong)stream.Id
                && frame.Offset == (ulong)payload.Length
                && frame.IsFin
                && frame.StreamDataLength == 0)
            {
                foundFinRepair = true;
                finRepairKeyPhase = keyPhase;
                finRepairFrame = frame;
                break;
            }
        }

        Assert.True(
            foundFinRepair,
            $"Expected PTO to retransmit the outstanding FIN-only close packet, but sent {string.Join(" || ", sendEffectDescriptions)}.");
        Assert.False(finRepairKeyPhase);
        Assert.Equal((ulong)stream.Id, finRepairFrame.StreamId.Value);
        Assert.Equal((ulong)payload.Length, finRepairFrame.Offset);
        Assert.True(finRepairFrame.IsFin);
        Assert.Equal(0, finRepairFrame.StreamDataLength);
    }

    [Theory]
    [InlineData(22)]
    [InlineData(24)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RecoveryTimerExpired_ReplaysOutstandingApplicationOpenAndFinishPacketsWithoutWaitingForAPeerAck(int payloadLength)
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedOpenPacket = FindTrackedPacket(runtime, openEffect.Datagram);
        outboundEffects.Clear();

        byte[] payload = CreateSequentialPayload(0x70, payloadLength);
        await stream.WriteAsync(payload, 0, payload.Length);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect finishEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedFinishPacket = FindTrackedPacket(runtime, finishEffect.Datagram);

        Assert.Equal(trackedOpenPacket.Key.PacketNumber + 1, trackedFinishPacket.Key.PacketNumber);

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
        string[] sendEffectDescriptions = sendEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        Assert.NotEmpty(sendEffects);
        Assert.DoesNotContain(sendEffects, sendEffect => IsPingOnlyPayload(runtime, sendEffect.Datagram));
        Assert.True(
            TryFindApplicationStreamProbeEffect(
                runtime,
                sendEffects,
                (ulong)stream.Id,
                payload,
                isFin: true,
                out bool finishKeyPhase),
            $"No PTO probe retransmitted the finished request packet. Sent={string.Join(" || ", sendEffectDescriptions)}");

        Assert.False(finishKeyPhase);
    }

    [Theory]
    [InlineData(22)]
    [InlineData(24)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RecoveryTimerExpired_StillRetransmitsOutstandingFinishedRequestAfterReceivingPeerApplicationPackets(int payloadLength)
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = CreateSequentialPayload(0x50, payloadLength);
        await stream.WriteAsync(payload, 0, payload.Length);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect finishEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        _ = FindTrackedPacket(runtime, finishEffect.Datagram);
        outboundEffects.Clear();

        byte[] peerPingPacket = BuildProtectedPeerPingPacket(runtime);
        QuicConnectionTransitionResult firstPeerPacketResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 100,
                runtime.ActivePath!.Value.Identity,
                peerPingPacket),
            nowTicks: 100);
        Assert.True(firstPeerPacketResult.StateChanged);

        QuicConnectionTransitionResult secondPeerPacketResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 200,
                runtime.ActivePath!.Value.Identity,
                peerPingPacket),
            nowTicks: 200);
        Assert.True(secondPeerPacketResult.StateChanged);

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
        string[] sendEffectDescriptions = sendEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        Assert.NotEmpty(sendEffects);
        Assert.DoesNotContain(sendEffects, sendEffect => IsPingOnlyPayload(runtime, sendEffect.Datagram));
        Assert.True(
            TryFindApplicationStreamProbeEffect(
                runtime,
                sendEffects,
                (ulong)stream.Id,
                payload,
                isFin: true,
                out bool finishKeyPhase),
            $"No PTO probe retransmitted the finished request packet after peer application traffic. Sent={string.Join(" || ", sendEffectDescriptions)}");
        Assert.False(finishKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProbeContent_RetransmitsPreviouslySentApplicationDataWhenNewDataIsUnavailable()
    {
        byte[] streamData = [0x10, 0x20, 0x30];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x06,
            streamData,
            offset: 0x11223344);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.True(frame.HasLength);
        Assert.Equal(0x11223344UL, frame.Offset);
        Assert.Equal((ulong)streamData.Length, frame.Length);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(frame.FrameType));

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frame.FrameType,
            frame.StreamId.Value,
            frame.Offset,
            frame.StreamData,
            destination,
            out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ProbeContent_FallsBackToPingWhenNoApplicationDataIsAvailable()
    {
        Span<byte> destination = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(destination[0]));

        Assert.True(QuicFrameCodec.TryParsePingFrame(destination, out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }

    private static byte[] BuildProtectedAckPacket(
        QuicConnectionRuntime runtime,
        ulong largestAcknowledged,
        ulong firstAckRange,
        QuicAckRange[] additionalRanges)
    {
        byte[] ackPayload = QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0,
            FirstAckRange = firstAckRange,
            AdditionalRanges = additionalRanges,
        });

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            ackPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static byte[] BuildProtectedPeerPingPacket(QuicConnectionRuntime runtime)
    {
        Span<byte> pingPayload = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(pingPayload, out int pingBytesWritten));

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            pingPayload[..pingBytesWritten],
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> FindTrackedPacket(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram)
    {
        return Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(datagram.Span));
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

        Assert.Fail("No Initial probe datagram was emitted when PTO expired.");
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

        Assert.Fail("No handshake PTO probe retransmitted the expected CRYPTO frame.");
        return default!;
    }

    private static QuicConnectionSendDatagramEffect FindApplicationStreamProbeEffect(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        ulong expectedStreamId,
        byte[] expectedPayload,
        bool isFin,
        out bool keyPhase)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (!TryOpenSingleStreamFrame(runtime, sendEffect.Datagram, out QuicStreamFrame frame, out keyPhase))
            {
                continue;
            }

            if (frame.StreamId.Value == expectedStreamId
                && frame.Offset == 0UL
                && frame.IsFin == isFin
                && frame.StreamData.SequenceEqual(expectedPayload))
            {
                return sendEffect;
            }
        }

        keyPhase = false;
        Assert.Fail("No PTO probe retransmitted the expected application STREAM frame.");
        return default!;
    }

    private static bool TryFindApplicationStreamProbeEffect(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        ulong expectedStreamId,
        byte[] expectedPayload,
        bool isFin,
        out bool keyPhase)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (!TryOpenSingleStreamFrame(runtime, sendEffect.Datagram, out QuicStreamFrame frame, out keyPhase))
            {
                continue;
            }

            if (frame.StreamId.Value == expectedStreamId
                && frame.Offset == 0UL
                && frame.IsFin == isFin
                && frame.StreamData.SequenceEqual(expectedPayload))
            {
                return true;
            }
        }

        keyPhase = false;
        return false;
    }

    private static bool TryFindApplicationStreamFrameAnywhere(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        ulong expectedStreamId,
        byte[] expectedPayload,
        bool isFin,
        out bool keyPhase)
    {
        keyPhase = false;

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
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

        ReadOnlySpan<byte> remaining = openedPacket.AsSpan(payloadOffset, payloadLength);
        while (!remaining.IsEmpty)
        {
            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                if (streamFrame.StreamId.Value == expectedStreamId
                    && streamFrame.Offset == 0UL
                    && streamFrame.IsFin == isFin
                    && streamFrame.StreamData.SequenceEqual(expectedPayload))
                {
                    return true;
                }

                remaining = remaining[streamFrame.ConsumedLength..];
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                remaining = remaining[ackBytesConsumed..];
                continue;
            }

            if (QuicFrameCodec.TryParseMaxStreamsFrame(remaining, out _, out int maxStreamsBytesConsumed))
            {
                remaining = remaining[maxStreamsBytesConsumed..];
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                remaining = remaining[pingBytesConsumed..];
                continue;
            }

            if (remaining[0] == 0x00)
            {
                int paddingLength = 0;
                while (paddingLength < remaining.Length && remaining[paddingLength] == 0x00)
                {
                    paddingLength++;
                }

                remaining = remaining[paddingLength..];
                continue;
            }

            return false;
        }

        return false;
    }

    private static QuicStreamFrame OpenSingleStreamFrame(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        out bool keyPhase)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
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

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
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

    private static bool IsPingOnlyPayload(QuicConnectionRuntime runtime, ReadOnlyMemory<byte> datagram)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        if (!coordinator.TryOpenProtectedApplicationDataPacket(
                datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out _))
        {
            return false;
        }

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        if (!QuicFrameCodec.TryParsePingFrame(payload, out int pingBytesConsumed))
        {
            return false;
        }

        for (int index = pingBytesConsumed; index < payload.Length; index++)
        {
            if (payload[index] != 0x00)
            {
                return false;
            }
        }

        return true;
    }

    private static string DescribeApplicationPayload(QuicConnectionRuntime runtime, ReadOnlyMemory<byte> datagram)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        if (!coordinator.TryOpenProtectedApplicationDataPacket(
                datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out bool keyPhase))
        {
            return $"unopened(len={datagram.Length})";
        }

        ReadOnlySpan<byte> remaining = openedPacket.AsSpan(payloadOffset, payloadLength);
        List<string> frames = [];

        while (!remaining.IsEmpty)
        {
            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                frames.Add(
                    $"stream(id={streamFrame.StreamId.Value},off={streamFrame.Offset},len={streamFrame.StreamDataLength},fin={streamFrame.IsFin})");
                remaining = remaining[streamFrame.ConsumedLength..];
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out QuicAckFrame ackFrame, out int ackBytesConsumed))
            {
                frames.Add($"ack(largest={ackFrame.LargestAcknowledged},first={ackFrame.FirstAckRange})");
                remaining = remaining[ackBytesConsumed..];
                continue;
            }

            if (QuicFrameCodec.TryParseMaxStreamsFrame(remaining, out QuicMaxStreamsFrame maxStreamsFrame, out int maxStreamsBytesConsumed))
            {
                frames.Add($"max_streams(bidi={maxStreamsFrame.IsBidirectional},max={maxStreamsFrame.MaximumStreams})");
                remaining = remaining[maxStreamsBytesConsumed..];
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                frames.Add("ping");
                remaining = remaining[pingBytesConsumed..];
                continue;
            }

            if (remaining[0] == 0x00)
            {
                int paddingLength = 0;
                while (paddingLength < remaining.Length && remaining[paddingLength] == 0x00)
                {
                    paddingLength++;
                }

                frames.Add($"padding({paddingLength})");
                remaining = remaining[paddingLength..];
                continue;
            }

            frames.Add($"unknown(0x{remaining[0]:X2})");
            break;
        }

        return $"keyPhase={keyPhase} {string.Join(",", frames)}";
    }

    private static QuicConnectionRuntime CreateEstablishingRuntimeWithActivePath()
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
            CreateSequentialPayload(0x51, 16),
            CreateSequentialPayload(0x61, 12),
            CreateSequentialPayload(0x71, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        return material;
    }

    private static byte[] CreateSequentialPayload(byte startValue, int length)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = unchecked((byte)(startValue + index));
        }

        return payload;
    }

    private sealed class FakeMonotonicClock(long ticks) : IMonotonicClock
    {
        public long Ticks { get; } = ticks;

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
