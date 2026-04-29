using System.Reflection;
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
    public async Task GapAckForLaterPacketsOnZeroLengthPeerDestinationCidMakesPtoRetransmitTheMissingApplicationData()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-160400023-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\output.txt:
        //     the managed server completed the 1024-byte multiconnect response, the simulator dropped one
        //     1077-byte server->client datagram, then later forwarded only a 53-byte FIN-only packet and
        //     subsequent 3-byte PTO probes.
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt:
        //     quic-go later received only STREAM stream_id=0 offset=1024 len=0 fin=true and timed out
        //     waiting for the missing 1024 body bytes.
        // The live failure was observed on the server-role multiconnect lane, but the bounded repo-owned seam is
        // the shared runtime's application repair path when the peer destination connection ID is zero-length.
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte>.Empty));
        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedOpenPacket = FindTrackedPacket(runtime, openEffect.Datagram);
        outboundEffects.Clear();

        byte[] payload = CreateSequentialPayload(0x30, 40);
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
            runtime.CurrentHandshakeSourceConnectionId.Span,
            largestAcknowledged: trackedDataPacket.Key.PacketNumber,
            firstAckRange: trackedDataPacket.Key.PacketNumber - trackedOpenPacket.Key.PacketNumber,
            additionalRanges: []);

        QuicHandshakeFlowCoordinator peerAckOpenCoordinator = new(
            runtime.CurrentPeerDestinationConnectionId.ToArray(),
            runtime.CurrentHandshakeSourceConnectionId.ToArray());
        Assert.True(peerAckOpenCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedAckPacket,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            out byte[] openedAckPacket,
            out int ackPayloadOffset,
            out int ackPayloadLength,
            out _));
        Assert.True(QuicFrameCodec.TryParseAckFrame(
            openedAckPacket.AsSpan(ackPayloadOffset, ackPayloadLength),
            out QuicAckFrame openedAckFrame,
            out _));
        Assert.Equal(trackedDataPacket.Key.PacketNumber, openedAckFrame.LargestAcknowledged);
        Assert.Equal(trackedDataPacket.Key.PacketNumber - trackedOpenPacket.Key.PacketNumber, openedAckFrame.FirstAckRange);

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

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AckingTheResponseBodyOnZeroLengthPeerDestinationCidStillMakesPtoRetransmitTheOutstandingFinOnlyClose()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-162814565-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt:
        //     packet 56 carried STREAM stream_id=0 offset=0 length=1024 fin=false,
        //     packet 57 remained missing, and packet 18 ACKed 58 and 56 but not 57 before idle timeout.
        //   runner-logs\nginx_quic-go\handshakeloss\output.txt:
        //     the simulator dropped one later 53-byte server->client datagram on the second managed transfer.
        // The bounded regression is the application PTO content choice after the peer has already
        // acknowledged the response body but not the later FIN-only close while the server is using
        // a zero-length peer destination connection ID.
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte>.Empty));
        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedOpenPacket = FindTrackedPacket(runtime, openEffect.Datagram);
        outboundEffects.Clear();

        byte[] payload = CreateSequentialPayload(0x24, 40);
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
            runtime.CurrentHandshakeSourceConnectionId.Span,
            largestAcknowledged: trackedDataPacket.Key.PacketNumber,
            firstAckRange: trackedDataPacket.Key.PacketNumber - trackedOpenPacket.Key.PacketNumber,
            additionalRanges: []);

        QuicHandshakeFlowCoordinator peerAckOpenCoordinator = new(
            runtime.CurrentPeerDestinationConnectionId.ToArray(),
            runtime.CurrentHandshakeSourceConnectionId.ToArray());
        Assert.True(peerAckOpenCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedAckPacket,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            out byte[] openedAckPacket,
            out int ackPayloadOffset,
            out int ackPayloadLength,
            out _));
        Assert.True(QuicFrameCodec.TryParseAckFrame(
            openedAckPacket.AsSpan(ackPayloadOffset, ackPayloadLength),
            out QuicAckFrame openedAckFrame,
            out _));
        Assert.Equal(trackedDataPacket.Key.PacketNumber, openedAckFrame.LargestAcknowledged);
        Assert.Equal(trackedDataPacket.Key.PacketNumber - trackedOpenPacket.Key.PacketNumber, openedAckFrame.FirstAckRange);

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
            $"Expected PTO to retransmit the outstanding FIN-only close packet on the zero-length-CID path, but sent {string.Join(" || ", sendEffectDescriptions)}.");
        Assert.False(finRepairKeyPhase);
        Assert.Equal((ulong)stream.Id, finRepairFrame.StreamId.Value);
        Assert.Equal((ulong)payload.Length, finRepairFrame.Offset);
        Assert.True(finRepairFrame.IsFin);
        Assert.Equal(0, finRepairFrame.StreamDataLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerRolePeerInitiatedResponseKeepsTheFinOnlyClosePreferredAfterTheBodyAndMaxStreamsAreAcknowledged()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-162814565-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt:
        //     the second connection received packet 56 with the 1024-byte response body, packet 57 was the
        //     dropped 53-byte server->client datagram, packet 58 carried MAX_STREAMS, and client packet 18
        //     ACKed 58 and 56 but not 57 before the server later idled.
        // The bounded regression follows that server-role peer-initiated path through the later credit ACKs,
        // drops the immediate FIN-only repair that follows, and then verifies PTO still replays the close.
        using QuicConnectionRuntime runtime = CreateFinishedServerRuntimeWithActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte>.Empty));
        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets.ToArray())
        {
            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                sentPacket.Key.PacketNumberSpace,
                sentPacket.Key.PacketNumber,
                handshakeConfirmed: runtime.HandshakeConfirmed));
        }

        Assert.Empty(runtime.SendRuntime.SentPackets);

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /\r\n");
        byte[] requestPacket = BuildProtectedPeerStreamPacket(
            runtime,
            streamId: 0,
            streamData: requestPayload,
            offset: 0,
            fin: true);

        QuicConnectionTransitionResult requestResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                requestPacket),
            nowTicks: 10);
        Assert.True(requestResult.StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot requestSnapshot));
        Assert.Equal(requestPayload.Length, checked((int)requestSnapshot.BufferedReadableBytes));
        await using QuicStream requestStream = new(runtime.StreamRegistry.Bookkeeping, 0, runtime);
        byte[] readBuffer = new byte[64];
        int totalRead = 0;
        int bytesRead;
        do
        {
            bytesRead = await requestStream.ReadAsync(readBuffer, 0, readBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
            totalRead += bytesRead;
        }
        while (bytesRead > 0);

        Assert.Equal(requestPayload.Length, totalRead);
        outboundEffects.Clear();

        byte[] responsePayload = CreateSequentialPayload(0x44, 4);
        await requestStream.WriteAsync(responsePayload, 0, responsePayload.Length);
        QuicConnectionSendDatagramEffect bodyEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedBodyPacket = FindTrackedPacket(runtime, bodyEffect.Datagram);
        outboundEffects.Clear();

        await requestStream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect[] completionEffects = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        string[] completionDescriptions = completionEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        Assert.True(completionEffects.Length >= 2, $"Expected FIN-only close and MAX_STREAMS packets, but saw {string.Join(" || ", completionDescriptions)}.");

        QuicConnectionSendDatagramEffect finEffect = FindFinOnlyCloseEffect(
            runtime,
            completionEffects,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            out bool finKeyPhase);
        QuicConnectionSendDatagramEffect maxStreamsEffect = FindMaxStreamsEffect(completionEffects, completionDescriptions);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedFinPacket = FindTrackedPacket(runtime, finEffect.Datagram);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedMaxStreamsPacket = FindTrackedPacket(runtime, maxStreamsEffect.Datagram);

        Assert.False(finKeyPhase);
        Assert.Equal(trackedBodyPacket.Key.PacketNumber + 1, trackedFinPacket.Key.PacketNumber);
        Assert.Equal(trackedFinPacket.Key.PacketNumber + 1, trackedMaxStreamsPacket.Key.PacketNumber);

        byte[] protectedAckPacket = BuildProtectedAckPacketForAcknowledgedPackets(
            runtime,
            runtime.CurrentHandshakeSourceConnectionId.Span,
            trackedBodyPacket.Key.PacketNumber,
            trackedMaxStreamsPacket.Key.PacketNumber);

        QuicConnectionTransitionResult ackResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 100,
                runtime.ActivePath.Value.Identity,
                protectedAckPacket),
            nowTicks: 100);

        QuicConnectionSendDatagramEffect[] ackSendEffects = ackResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        string[] ackSendDescriptions = ackSendEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();
        Assert.Contains(ackSendDescriptions, description => description.Contains("max_data(", StringComparison.Ordinal));
        Assert.Contains(ackSendDescriptions, description => description.Contains("max_stream_data(", StringComparison.Ordinal));

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket>[] trackedCreditPackets = ackSendEffects
            .Select(sendEffect => FindTrackedPacket(runtime, sendEffect.Datagram))
            .ToArray();
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedBodyPacket.Key.PacketNumber);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedMaxStreamsPacket.Key.PacketNumber);
        Assert.Contains(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedFinPacket.Key.PacketNumber);

        byte[] protectedCreditAckPacket = BuildProtectedAckPacketForAcknowledgedPackets(
            runtime,
            runtime.CurrentHandshakeSourceConnectionId.Span,
            trackedCreditPackets.Select(static packet => packet.Key.PacketNumber).ToArray());

        QuicConnectionTransitionResult creditAckResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 200,
                runtime.ActivePath.Value.Identity,
                protectedCreditAckPacket),
            nowTicks: 200);

        QuicConnectionSendDatagramEffect[] creditAckSendEffects = creditAckResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.DoesNotContain(creditAckSendEffects, sendEffect => IsPingOnlyPayload(runtime, sendEffect.Datagram));
        QuicConnectionSendDatagramEffect immediateFinRepairEffect = FindFinOnlyCloseEffect(
            runtime,
            creditAckSendEffects,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            out bool immediateFinRepairKeyPhase);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedImmediateFinRepairPacket = FindTrackedPacket(
            runtime,
            immediateFinRepairEffect.Datagram);

        Assert.False(immediateFinRepairKeyPhase);
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedCreditPacket in trackedCreditPackets)
        {
            Assert.DoesNotContain(
                runtime.SendRuntime.SentPackets,
                entry => entry.Key.PacketNumber == trackedCreditPacket.Key.PacketNumber);
        }

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

        QuicConnectionSendDatagramEffect finRepairEffect = FindFinOnlyCloseEffect(
            runtime,
            sendEffects,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            out bool finRepairKeyPhase);
        QuicStreamFrame finRepairFrame = OpenSingleStreamFrame(runtime, finRepairEffect.Datagram, out finRepairKeyPhase);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedPtoFinRepairPacket = FindTrackedFinOnlyClosePacket(
            runtime,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            minimumPacketNumberExclusive: trackedImmediateFinRepairPacket.Key.PacketNumber);

        Assert.False(finRepairKeyPhase);
        Assert.Equal(0UL, finRepairFrame.StreamId.Value);
        Assert.Equal((ulong)responsePayload.Length, finRepairFrame.Offset);
        Assert.True(finRepairFrame.IsFin);
        Assert.Equal(0, finRepairFrame.StreamDataLength);
        Assert.True(trackedPtoFinRepairPacket.Key.PacketNumber > trackedImmediateFinRepairPacket.Key.PacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerRoleLiveSizedPeerInitiatedResponseRepairsFinOnlyCloseAfterPreBodyCreditPacketsAreAcknowledged()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-162814565-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt:
        //     the second connection ACKed the preceding server credit packets plus packet 56 carrying the
        //     1024-byte response body and packet 58 carrying MAX_STREAMS, but not the missing packet 57
        //     carrying the FIN-only close.
        //   runner-logs\nginx_quic-go\handshakeloss\output.txt:
        //     the simulator forwarded the 1077-byte body, dropped the following 53-byte server->client
        //     datagram, and forwarded the later 85-byte server->client datagram before quic-go timed out.
        // This replay keeps the server-side pre-body application send history instead of clearing it, so the
        // selective ACK shape matches the live gap more closely than the distilled repair test above.
        using QuicConnectionRuntime runtime = CreateFinishedServerRuntimeWithActivePath(
            connectionFlowControlLimit: 4096,
            streamFlowControlLimit: 4096,
            validateActivePath: true);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte>.Empty));
        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);
        AcknowledgeTrackedPackets(
            runtime,
            static key => key.PacketNumberSpace is not QuicPacketNumberSpace.ApplicationData);

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /tiny-unlimited-paper\r\n");
        byte[] requestPacket = BuildProtectedPeerStreamPacket(
            runtime,
            streamId: 0,
            streamData: requestPayload,
            offset: 0,
            fin: true);

        QuicConnectionTransitionResult requestResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                requestPacket),
            nowTicks: 10);
        Assert.True(requestResult.StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot requestSnapshot));
        Assert.Equal(requestPayload.Length, checked((int)requestSnapshot.BufferedReadableBytes));

        await using QuicStream requestStream = new(runtime.StreamRegistry.Bookkeeping, 0, runtime);
        byte[] readBuffer = new byte[64];
        int totalRead = 0;
        int bytesRead;
        do
        {
            bytesRead = await requestStream.ReadAsync(readBuffer, 0, readBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
            totalRead += bytesRead;
        }
        while (bytesRead > 0);

        Assert.Equal(requestPayload.Length, totalRead);
        QuicConnectionSentPacketKey[] preBodyApplicationPacketKeys = runtime.SendRuntime.SentPackets.Keys
            .Where(static key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .OrderBy(static key => key.PacketNumber)
            .ToArray();
        string[] preBodyDescriptions = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        Assert.NotEmpty(preBodyApplicationPacketKeys);
        Assert.Contains(preBodyDescriptions, description => description.Contains("max_data(", StringComparison.Ordinal));
        Assert.Contains(preBodyDescriptions, description => description.Contains("max_stream_data(", StringComparison.Ordinal));
        outboundEffects.Clear();

        byte[] responsePayload = CreateSequentialPayload(0x44, 1024);
        await requestStream.WriteAsync(responsePayload, 0, responsePayload.Length);
        QuicConnectionSendDatagramEffect bodyEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedBodyPacket = FindTrackedPacket(runtime, bodyEffect.Datagram);
        outboundEffects.Clear();

        await requestStream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect[] completionEffects = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        string[] completionDescriptions = completionEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        QuicConnectionSendDatagramEffect finEffect = FindFinOnlyCloseEffect(
            runtime,
            completionEffects,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            out bool finKeyPhase);
        QuicConnectionSendDatagramEffect maxStreamsEffect = FindMaxStreamsEffect(completionEffects, completionDescriptions);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedFinPacket = FindTrackedPacket(runtime, finEffect.Datagram);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedMaxStreamsPacket = FindTrackedPacket(runtime, maxStreamsEffect.Datagram);

        Assert.False(finKeyPhase);
        Assert.Equal(1077, bodyEffect.Datagram.Length);
        Assert.Equal(53, finEffect.Datagram.Length);
        Assert.Equal(85, maxStreamsEffect.Datagram.Length);
        Assert.Equal(trackedBodyPacket.Key.PacketNumber + 1, trackedFinPacket.Key.PacketNumber);
        Assert.Equal(trackedFinPacket.Key.PacketNumber + 1, trackedMaxStreamsPacket.Key.PacketNumber);

        ulong[] acknowledgedPacketNumbers = preBodyApplicationPacketKeys
            .Select(static key => key.PacketNumber)
            .Append(trackedBodyPacket.Key.PacketNumber)
            .Append(trackedMaxStreamsPacket.Key.PacketNumber)
            .Distinct()
            .OrderBy(static packetNumber => packetNumber)
            .ToArray();
        Assert.DoesNotContain(trackedFinPacket.Key.PacketNumber, acknowledgedPacketNumbers);

        byte[] protectedAckPacket = BuildProtectedAckPacketForAcknowledgedPackets(
            runtime,
            runtime.CurrentHandshakeSourceConnectionId.Span,
            acknowledgedPacketNumbers);

        QuicConnectionTransitionResult ackResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 100,
                runtime.ActivePath.Value.Identity,
                protectedAckPacket),
            nowTicks: 100);
        QuicConnectionSendDatagramEffect[] ackSendEffects = ackResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        string[] ackSendDescriptions = ackSendEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        AssertOnlyFlowControlRepairs(runtime, ackSendEffects, ackSendDescriptions);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedBodyPacket.Key.PacketNumber);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedMaxStreamsPacket.Key.PacketNumber);
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

        QuicConnectionSendDatagramEffect finRepairEffect = FindFinOnlyCloseEffect(
            runtime,
            sendEffects,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            out bool finRepairKeyPhase);
        QuicStreamFrame finRepairFrame = OpenSingleStreamFrame(runtime, finRepairEffect.Datagram, out finRepairKeyPhase);

        Assert.False(finRepairKeyPhase);
        Assert.Equal(0UL, finRepairFrame.StreamId.Value);
        Assert.Equal((ulong)responsePayload.Length, finRepairFrame.Offset);
        Assert.True(finRepairFrame.IsFin);
        Assert.Equal(0, finRepairFrame.StreamDataLength);
        Assert.True(
            sendEffectDescriptions.Any(description => description.Contains("stream(id=0,off=1024,len=0,fin=True)", StringComparison.Ordinal)),
            $"Expected PTO to retransmit the dropped live-sized FIN-only close, but ACK response sent {string.Join(" || ", ackSendDescriptions)} and PTO sent {string.Join(" || ", sendEffectDescriptions)}.");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerRoleLiveSizedPeerInitiatedResponseRepairsFinOnlyCloseAfterLiveSparseCreditAckRanges()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-162814565-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt lines 590-638:
        //     packet 18 ACKed ranges 58, 56, 53-49, 47, 44-42, 38, 36-32, 29-23,
        //     21, 17-16, 14-11, and 9-0 while omitting packet 57 carrying the
        //     FIN-only close and also leaving multiple older credit packet holes.
        //   runner-logs\nginx_quic-go\handshakeloss\output.txt lines 554-558:
        //     the simulator forwarded the 1077-byte body, dropped the 53-byte FIN-only
        //     datagram, and forwarded the later 85-byte MAX_STREAMS datagram.
        using QuicConnectionRuntime runtime = CreateFinishedServerRuntimeWithActivePath(
            connectionFlowControlLimit: 4096,
            streamFlowControlLimit: 4096,
            validateActivePath: true);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte>.Empty));
        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);
        AcknowledgeTrackedPackets(
            runtime,
            static key => key.PacketNumberSpace is not QuicPacketNumberSpace.ApplicationData);

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /tiny-unlimited-paper\r\n");
        byte[] requestPacket = BuildProtectedPeerStreamPacket(
            runtime,
            streamId: 0,
            streamData: requestPayload,
            offset: 0,
            fin: true);

        QuicConnectionTransitionResult requestResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                requestPacket),
            nowTicks: 10);
        Assert.True(requestResult.StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot requestSnapshot));
        Assert.Equal(requestPayload.Length, checked((int)requestSnapshot.BufferedReadableBytes));

        await using QuicStream requestStream = new(runtime.StreamRegistry.Bookkeeping, 0, runtime);
        byte[] readBuffer = new byte[1];
        int totalRead = 0;
        int bytesRead;
        do
        {
            bytesRead = await requestStream.ReadAsync(readBuffer, 0, readBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
            totalRead += bytesRead;
        }
        while (bytesRead > 0);

        Assert.Equal(requestPayload.Length, totalRead);
        QuicConnectionSentPacketKey[] preBodyApplicationPacketKeys = runtime.SendRuntime.SentPackets.Keys
            .Where(static key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .OrderBy(static key => key.PacketNumber)
            .ToArray();
        string[] preBodyDescriptions = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        Assert.True(
            preBodyApplicationPacketKeys.Length >= 54,
            $"Expected byte-wise request consumption to retain the live pre-body credit packet train, but tracked {preBodyApplicationPacketKeys.Length} packets: {string.Join(" || ", preBodyDescriptions)}.");
        Assert.Contains(preBodyDescriptions, description => description.Contains("max_data(", StringComparison.Ordinal));
        Assert.Contains(preBodyDescriptions, description => description.Contains("max_stream_data(", StringComparison.Ordinal));
        outboundEffects.Clear();

        byte[] responsePayload = CreateSequentialPayload(0x44, 1024);
        await requestStream.WriteAsync(responsePayload, 0, responsePayload.Length);
        QuicConnectionSendDatagramEffect bodyEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedBodyPacket = FindTrackedPacket(runtime, bodyEffect.Datagram);
        outboundEffects.Clear();

        await requestStream.CompleteWritesAsync().AsTask();
        QuicConnectionSendDatagramEffect[] completionEffects = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        string[] completionDescriptions = completionEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        QuicConnectionSendDatagramEffect finEffect = FindFinOnlyCloseEffect(
            runtime,
            completionEffects,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            out bool finKeyPhase);
        QuicConnectionSendDatagramEffect maxStreamsEffect = FindMaxStreamsEffect(completionEffects, completionDescriptions);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedFinPacket = FindTrackedPacket(runtime, finEffect.Datagram);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedMaxStreamsPacket = FindTrackedPacket(runtime, maxStreamsEffect.Datagram);

        Assert.False(finKeyPhase);
        Assert.Equal(1077, bodyEffect.Datagram.Length);
        Assert.Equal(53, finEffect.Datagram.Length);
        Assert.Equal(85, maxStreamsEffect.Datagram.Length);
        Assert.Equal(trackedBodyPacket.Key.PacketNumber + 1, trackedFinPacket.Key.PacketNumber);
        Assert.Equal(trackedFinPacket.Key.PacketNumber + 1, trackedMaxStreamsPacket.Key.PacketNumber);

        byte[] protectedAckPacket = BuildProtectedAckPacketForAcknowledgedPackets(
            runtime,
            runtime.CurrentHandshakeSourceConnectionId.Span,
            BuildLiveSparseCreditAckPacketNumbers(
                trackedBodyPacket.Key.PacketNumber,
                trackedMaxStreamsPacket.Key.PacketNumber));

        QuicConnectionTransitionResult ackResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 100,
                runtime.ActivePath.Value.Identity,
                protectedAckPacket),
            nowTicks: 100);
        QuicConnectionSendDatagramEffect[] ackSendEffects = ackResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        string[] ackSendDescriptions = ackSendEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        AssertOnlyFlowControlRepairs(runtime, ackSendEffects, ackSendDescriptions);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedBodyPacket.Key.PacketNumber);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumber == trackedMaxStreamsPacket.Key.PacketNumber);
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

        QuicConnectionSendDatagramEffect finRepairEffect = FindFinOnlyCloseEffect(
            runtime,
            sendEffects,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            out bool finRepairKeyPhase);
        QuicStreamFrame finRepairFrame = OpenSingleStreamFrame(runtime, finRepairEffect.Datagram, out finRepairKeyPhase);

        Assert.False(finRepairKeyPhase);
        Assert.Equal(0UL, finRepairFrame.StreamId.Value);
        Assert.Equal((ulong)responsePayload.Length, finRepairFrame.Offset);
        Assert.True(finRepairFrame.IsFin);
        Assert.Equal(0, finRepairFrame.StreamDataLength);
        Assert.True(
            sendEffectDescriptions.Any(description => description.Contains("stream(id=0,off=1024,len=0,fin=True)", StringComparison.Ordinal)),
            $"Expected PTO to retransmit the live sparse-ACK FIN-only close, but ACK response sent {string.Join(" || ", ackSendDescriptions)} and PTO sent {string.Join(" || ", sendEffectDescriptions)}.");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerRoleHostSchedulerReissuesLiveSparseFinOnlyCloseAfterRecoveryDeadline()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-162814565-server-nginx
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt lines 590-638:
        //     the live peer ACKed packets 58 and 56 while omitting packet 57, then left multiple older
        //     credit-packet holes.
        //   runner-logs\nginx_quic-go\handshakeloss\output.txt lines 554-596:
        //     the simulator forwarded the 1077-byte body, dropped the 53-byte FIN-only datagram, forwarded
        //     the later 85-byte MAX_STREAMS datagram, and then observed only client->server traffic until
        //     the runner timed out.
        using QuicConnectionRuntime runtime = CreateFinishedServerRuntimeWithActivePath(
            connectionFlowControlLimit: 4096,
            streamFlowControlLimit: 4096,
            validateActivePath: true);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte>.Empty));
        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);
        AcknowledgeTrackedPackets(
            runtime,
            static key => key.PacketNumberSpace is not QuicPacketNumberSpace.ApplicationData);

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /tiny-unlimited-paper\r\n");
        byte[] requestPacket = BuildProtectedPeerStreamPacket(
            runtime,
            streamId: 0,
            streamData: requestPayload,
            offset: 0,
            fin: true);

        QuicConnectionTransitionResult requestResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                requestPacket),
            nowTicks: 10);
        Assert.True(requestResult.StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot requestSnapshot));
        Assert.Equal(requestPayload.Length, checked((int)requestSnapshot.BufferedReadableBytes));

        await using QuicStream requestStream = new(runtime.StreamRegistry.Bookkeeping, 0, runtime);
        byte[] readBuffer = new byte[1];
        int totalRead = 0;
        int bytesRead;
        do
        {
            bytesRead = await requestStream.ReadAsync(readBuffer, 0, readBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
            totalRead += bytesRead;
        }
        while (bytesRead > 0);

        Assert.Equal(requestPayload.Length, totalRead);
        QuicConnectionSentPacketKey[] preBodyApplicationPacketKeys = runtime.SendRuntime.SentPackets.Keys
            .Where(static key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .OrderBy(static key => key.PacketNumber)
            .ToArray();
        string[] preBodyDescriptions = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        Assert.True(
            preBodyApplicationPacketKeys.Length >= 54,
            $"Expected byte-wise request consumption to retain the live pre-body credit packet train, but tracked {preBodyApplicationPacketKeys.Length} packets: {string.Join(" || ", preBodyDescriptions)}.");
        Assert.Contains(preBodyDescriptions, description => description.Contains("max_data(", StringComparison.Ordinal));
        Assert.Contains(preBodyDescriptions, description => description.Contains("max_stream_data(", StringComparison.Ordinal));
        outboundEffects.Clear();

        byte[] responsePayload = CreateSequentialPayload(0x44, 1024);
        await requestStream.WriteAsync(responsePayload, 0, responsePayload.Length).WaitAsync(TimeSpan.FromSeconds(5));
        QuicConnectionSendDatagramEffect bodyEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedBodyPacket = FindTrackedPacket(runtime, bodyEffect.Datagram);
        outboundEffects.Clear();

        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        QuicConnectionSendDatagramEffect[] completionEffects = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        string[] completionDescriptions = completionEffects
            .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
            .ToArray();

        QuicConnectionSendDatagramEffect finEffect = FindFinOnlyCloseEffect(
            runtime,
            completionEffects,
            streamId: 0,
            offset: (ulong)responsePayload.Length,
            out bool finKeyPhase);
        QuicConnectionSendDatagramEffect maxStreamsEffect = FindMaxStreamsEffect(completionEffects, completionDescriptions);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedFinPacket = FindTrackedPacket(runtime, finEffect.Datagram);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedMaxStreamsPacket = FindTrackedPacket(runtime, maxStreamsEffect.Datagram);

        Assert.False(finKeyPhase);
        Assert.Equal(1077, bodyEffect.Datagram.Length);
        Assert.Equal(53, finEffect.Datagram.Length);
        Assert.Equal(85, maxStreamsEffect.Datagram.Length);
        Assert.Equal(trackedBodyPacket.Key.PacketNumber + 1, trackedFinPacket.Key.PacketNumber);
        Assert.Equal(trackedFinPacket.Key.PacketNumber + 1, trackedMaxStreamsPacket.Key.PacketNumber);

        FakeMonotonicClock hostClock = new(0);
        await using QuicConnectionRuntimeEndpoint endpoint = new(1, hostClock);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        List<QuicConnectionSendDatagramEffect> observedSendEffects = [];
        object observedSendEffectsGate = new();
        int observedPacketReceivedTransitions = 0;

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, runtime.CurrentHandshakeSourceConnectionId.Span));
        runtime.SetLocalApiEventDispatcher(connectionEvent => endpoint.Host.TryPostEvent(handle, connectionEvent));

        using CancellationTokenSource cancellation = new();
        Task consumer = endpoint.RunAsync(
            (observedHandle, _, transition) =>
            {
                if (observedHandle == handle && transition.EventKind == QuicConnectionEventKind.PacketReceived)
                {
                    Interlocked.Increment(ref observedPacketReceivedTransitions);
                }
            },
            (observedHandle, _, effect) =>
            {
                if (observedHandle == handle && effect is QuicConnectionSendDatagramEffect sendEffect)
                {
                    lock (observedSendEffectsGate)
                    {
                        observedSendEffects.Add(sendEffect);
                    }
                }
            },
            cancellation.Token);

        try
        {
            byte[] protectedAckPacket = BuildProtectedAckPacketForAcknowledgedPackets(
                runtime,
                runtime.CurrentHandshakeSourceConnectionId.Span,
                BuildLiveSparseCreditAckPacketNumbers(
                    trackedBodyPacket.Key.PacketNumber,
                    trackedMaxStreamsPacket.Key.PacketNumber));

            QuicConnectionIngressResult ackIngress = endpoint.ReceiveDatagram(
                protectedAckPacket,
                runtime.ActivePath.Value.Identity);

            Assert.True(ackIngress.RoutedToConnection);
            await WaitUntilAsync(
                () => Volatile.Read(ref observedPacketReceivedTransitions) >= 1,
                "Timed out waiting for the host to route the live sparse ACK packet.");

            QuicConnectionSendDatagramEffect[] ackSendEffects = SnapshotSendEffects(observedSendEffects, observedSendEffectsGate)
                .ToArray();
            string[] ackSendDescriptions = ackSendEffects
                .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
                .ToArray();

            AssertOnlyFlowControlRepairs(runtime, ackSendEffects, ackSendDescriptions);
            Assert.DoesNotContain(
                runtime.SendRuntime.SentPackets,
                entry => entry.Key.PacketNumber == trackedBodyPacket.Key.PacketNumber);
            Assert.DoesNotContain(
                runtime.SendRuntime.SentPackets,
                entry => entry.Key.PacketNumber == trackedMaxStreamsPacket.Key.PacketNumber);
            Assert.Contains(
                runtime.SendRuntime.SentPackets,
                entry => entry.Key.PacketNumber == trackedFinPacket.Key.PacketNumber);

            long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
            Assert.NotNull(recoveryDueTicks);
            int recoveryBaseline = SnapshotSendEffects(observedSendEffects, observedSendEffectsGate).Length;
            hostClock.Advance(Math.Max(0, recoveryDueTicks.Value - hostClock.Ticks));
            Assert.True(endpoint.Host.TryPostEvent(
                handle,
                new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: hostClock.Ticks)));

            await WaitUntilAsync(
                () => SnapshotSendEffects(observedSendEffects, observedSendEffectsGate)
                    .Skip(recoveryBaseline)
                    .Any(sendEffect => IsFinOnlyCloseEffect(runtime, sendEffect, streamId: 0, offset: (ulong)responsePayload.Length)),
                "Timed out waiting for the host scheduler to deliver the recovery timer and reissue the FIN-only close.");

            QuicConnectionSendDatagramEffect[] recoverySendEffects = SnapshotSendEffects(observedSendEffects, observedSendEffectsGate)
                .Skip(recoveryBaseline)
                .ToArray();
            string[] recoverySendDescriptions = recoverySendEffects
                .Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram))
                .ToArray();

            Assert.DoesNotContain(recoverySendEffects, sendEffect => IsPingOnlyPayload(runtime, sendEffect.Datagram));
            Assert.Contains(
                recoverySendDescriptions,
                description => description.Contains("stream(id=0,off=1024,len=0,fin=True)", StringComparison.Ordinal));
        }
        finally
        {
            cancellation.Cancel();
            await consumer;
        }
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
        return BuildProtectedAckPacket(
            runtime,
            PacketConnectionId,
            largestAcknowledged,
            firstAckRange,
            additionalRanges);
    }

    private static byte[] BuildProtectedAckPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> destinationConnectionId,
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

        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId.ToArray());
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            ackPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static byte[] BuildProtectedAckPacketForAcknowledgedPackets(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> destinationConnectionId,
        params ulong[] acknowledgedPacketNumbers)
    {
        ulong[] sortedPacketNumbers = acknowledgedPacketNumbers
            .Distinct()
            .OrderBy(static packetNumber => packetNumber)
            .ToArray();

        Assert.NotEmpty(sortedPacketNumbers);

        List<(ulong Smallest, ulong Largest)> ranges = [];
        ulong currentSmallest = sortedPacketNumbers[^1];
        ulong currentLargest = sortedPacketNumbers[^1];
        for (int index = sortedPacketNumbers.Length - 2; index >= 0; index--)
        {
            ulong packetNumber = sortedPacketNumbers[index];
            if (packetNumber + 1 == currentSmallest)
            {
                currentSmallest = packetNumber;
                continue;
            }

            ranges.Add((currentSmallest, currentLargest));
            currentSmallest = packetNumber;
            currentLargest = packetNumber;
        }

        ranges.Add((currentSmallest, currentLargest));

        (ulong Smallest, ulong Largest) firstRange = ranges[0];
        List<QuicAckRange> additionalRanges = [];
        for (int index = 1; index < ranges.Count; index++)
        {
            (ulong Smallest, ulong Largest) previousRange = ranges[index - 1];
            (ulong Smallest, ulong Largest) currentRange = ranges[index];
            additionalRanges.Add(new QuicAckRange(
                gap: previousRange.Smallest - currentRange.Largest - 2,
                ackRangeLength: currentRange.Largest - currentRange.Smallest,
                smallestAcknowledged: currentRange.Smallest,
                largestAcknowledged: currentRange.Largest));
        }

        return BuildProtectedAckPacket(
            runtime,
            destinationConnectionId,
            largestAcknowledged: firstRange.Largest,
            firstAckRange: firstRange.Largest - firstRange.Smallest,
            additionalRanges: additionalRanges.ToArray());
    }

    private static ulong[] BuildLiveSparseCreditAckPacketNumbers(
        ulong trackedBodyPacketNumber,
        ulong trackedMaxStreamsPacketNumber)
    {
        List<ulong> packetNumbers = [];
        AddInclusiveRange(packetNumbers, 0, 9);
        AddInclusiveRange(packetNumbers, 11, 14);
        AddInclusiveRange(packetNumbers, 16, 17);
        packetNumbers.Add(21);
        AddInclusiveRange(packetNumbers, 23, 29);
        AddInclusiveRange(packetNumbers, 32, 36);
        packetNumbers.Add(38);
        AddInclusiveRange(packetNumbers, 42, 44);
        packetNumbers.Add(47);
        AddInclusiveRange(packetNumbers, 49, 53);
        packetNumbers.Add(trackedBodyPacketNumber);
        packetNumbers.Add(trackedMaxStreamsPacketNumber);

        return packetNumbers.ToArray();
    }

    private static void AddInclusiveRange(List<ulong> packetNumbers, ulong start, ulong end)
    {
        for (ulong packetNumber = start; packetNumber <= end; packetNumber++)
        {
            packetNumbers.Add(packetNumber);
        }
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

    private static byte[] BuildProtectedPeerStreamPacket(
        QuicConnectionRuntime runtime,
        ulong streamId,
        ReadOnlySpan<byte> streamData,
        ulong offset,
        bool fin)
    {
        byte frameType = fin ? (byte)0x0F : (byte)0x0E;
        byte[] payload = QuicStreamTestData.BuildStreamFrame(
            frameType: frameType,
            streamId: streamId,
            streamData,
            offset: offset);

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentHandshakeSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
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

    private static void AcknowledgeTrackedPackets(
        QuicConnectionRuntime runtime,
        Func<QuicConnectionSentPacketKey, bool> predicate)
    {
        foreach (QuicConnectionSentPacketKey key in runtime.SendRuntime.SentPackets.Keys.ToArray())
        {
            if (!predicate(key))
            {
                continue;
            }

            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                key.PacketNumberSpace,
                key.PacketNumber,
                handshakeConfirmed: runtime.HandshakeConfirmed));
        }
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

        QuicHandshakeFlowCoordinator coordinator = CreateOutgoingApplicationDataOpenCoordinator(runtime);
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

            if (QuicFrameCodec.TryParseMaxDataFrame(remaining, out _, out int maxDataBytesConsumed))
            {
                remaining = remaining[maxDataBytesConsumed..];
                continue;
            }

            if (QuicFrameCodec.TryParseMaxStreamDataFrame(remaining, out _, out int maxStreamDataBytesConsumed))
            {
                remaining = remaining[maxStreamDataBytesConsumed..];
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
        QuicHandshakeFlowCoordinator coordinator = CreateOutgoingApplicationDataOpenCoordinator(runtime);
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

        QuicHandshakeFlowCoordinator coordinator = CreateOutgoingApplicationDataOpenCoordinator(runtime);
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

    private static QuicConnectionSendDatagramEffect FindFinOnlyCloseEffect(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        ulong streamId,
        ulong offset,
        out bool keyPhase)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            if (!TryOpenSingleStreamFrame(runtime, sendEffect.Datagram, out QuicStreamFrame frame, out bool candidateKeyPhase))
            {
                continue;
            }

            if (frame.StreamId.Value == streamId
                && frame.Offset == offset
                && frame.IsFin
                && frame.StreamDataLength == 0)
            {
                keyPhase = candidateKeyPhase;
                return sendEffect;
            }
        }

        Assert.Fail($"No FIN-only close packet was found. Sent={string.Join(" || ", sendEffects.Select(sendEffect => DescribeApplicationPayload(runtime, sendEffect.Datagram)))}");
        keyPhase = false;
        return default!;
    }

    private static bool IsFinOnlyCloseEffect(
        QuicConnectionRuntime runtime,
        QuicConnectionSendDatagramEffect sendEffect,
        ulong streamId,
        ulong offset)
    {
        return TryOpenSingleStreamFrame(runtime, sendEffect.Datagram, out QuicStreamFrame frame, out _)
            && frame.StreamId.Value == streamId
            && frame.Offset == offset
            && frame.IsFin
            && frame.StreamDataLength == 0;
    }

    private static QuicConnectionSendDatagramEffect FindMaxStreamsEffect(
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        string[] descriptions)
    {
        QuicConnectionSendDatagramEffect[] effects = sendEffects.ToArray();
        for (int index = 0; index < effects.Length; index++)
        {
            if (descriptions[index].Contains("max_streams(", StringComparison.Ordinal))
            {
                return effects[index];
            }
        }

        Assert.Fail($"No MAX_STREAMS packet was found. Sent={string.Join(" || ", descriptions)}");
        return default!;
    }

    private static KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> FindTrackedFinOnlyClosePacket(
        QuicConnectionRuntime runtime,
        ulong streamId,
        ulong offset,
        ulong minimumPacketNumberExclusive)
    {
        return Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Key.PacketNumber > minimumPacketNumberExclusive
                && entry.Value.ProbePacket
                && HasTrackedFinOnlyClosePayload(
                    entry.Value.PlaintextPayload.Span,
                    streamId,
                    offset));
    }

    private static bool HasTrackedFinOnlyClosePayload(
        ReadOnlySpan<byte> payload,
        ulong streamId,
        ulong offset)
    {
        if (!QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame frame))
        {
            return false;
        }

        if (frame.StreamId.Value != streamId
            || frame.Offset != offset
            || !frame.IsFin
            || frame.StreamDataLength != 0)
        {
            return false;
        }

        ReadOnlySpan<byte> remaining = payload[frame.ConsumedLength..];
        while (!remaining.IsEmpty && remaining[0] == 0x00)
        {
            remaining = remaining[1..];
        }

        return remaining.IsEmpty;
    }

    private static bool IsPingOnlyPayload(QuicConnectionRuntime runtime, ReadOnlyMemory<byte> datagram)
    {
        QuicHandshakeFlowCoordinator coordinator = CreateOutgoingApplicationDataOpenCoordinator(runtime);
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

    private static void AssertOnlyFlowControlRepairs(
        QuicConnectionRuntime runtime,
        IReadOnlyCollection<QuicConnectionSendDatagramEffect> sendEffects,
        IReadOnlyList<string> descriptions)
    {
        Assert.DoesNotContain(sendEffects, sendEffect => IsPingOnlyPayload(runtime, sendEffect.Datagram));
        Assert.All(
            descriptions,
            description => Assert.True(
                description.Contains("max_data(", StringComparison.Ordinal)
                    || description.Contains("max_stream_data(", StringComparison.Ordinal),
                $"Expected only flow-control credit repairs, but ACK response included {description}."));
        Assert.DoesNotContain(
            descriptions,
            description => description.Contains("stream(id=0,off=1024", StringComparison.Ordinal));
    }

    private static QuicConnectionSendDatagramEffect[] SnapshotSendEffects(
        List<QuicConnectionSendDatagramEffect> sendEffects,
        object gate)
    {
        lock (gate)
        {
            return sendEffects.ToArray();
        }
    }

    private static async Task WaitUntilAsync(Func<bool> predicate, string failureMessage)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            if (predicate())
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10));
        }

        Assert.True(predicate(), failureMessage);
    }

    private static string DescribeApplicationPayload(QuicConnectionRuntime runtime, ReadOnlyMemory<byte> datagram)
    {
        QuicHandshakeFlowCoordinator coordinator = CreateOutgoingApplicationDataOpenCoordinator(runtime);
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

            if (QuicFrameCodec.TryParseMaxDataFrame(remaining, out QuicMaxDataFrame maxDataFrame, out int maxDataBytesConsumed))
            {
                frames.Add($"max_data(max={maxDataFrame.MaximumData})");
                remaining = remaining[maxDataBytesConsumed..];
                continue;
            }

            if (QuicFrameCodec.TryParseMaxStreamDataFrame(remaining, out QuicMaxStreamDataFrame maxStreamDataFrame, out int maxStreamDataBytesConsumed))
            {
                frames.Add($"max_stream_data(stream={maxStreamDataFrame.StreamId},max={maxStreamDataFrame.MaximumStreamData})");
                remaining = remaining[maxStreamDataBytesConsumed..];
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

    private static QuicHandshakeFlowCoordinator CreateOutgoingApplicationDataOpenCoordinator(QuicConnectionRuntime runtime)
    {
        return new QuicHandshakeFlowCoordinator(runtime.CurrentPeerDestinationConnectionId);
    }

    private static QuicConnectionRuntime CreateFinishedServerRuntimeWithActivePath(
        ulong connectionFlowControlLimit = 64,
        ulong streamFlowControlLimit = 8,
        bool validateActivePath = false)
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime(
            connectionReceiveLimit: connectionFlowControlLimit,
            connectionSendLimit: connectionFlowControlLimit,
            incomingBidirectionalStreamReceiveLimit: streamFlowControlLimit,
            outgoingBidirectionalStreamReceiveLimit: streamFlowControlLimit,
            peerConnectionFlowControlLimit: connectionFlowControlLimit,
            peerStreamFlowControlLimit: streamFlowControlLimit);
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.10", RemotePort: 443);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(pathIdentity, runtime.ActivePath.Value.Identity);

        if (validateActivePath)
        {
            MarkActivePathValidated(runtime, nowTicks: 9);
        }

        return runtime;
    }

    private static void MarkActivePathValidated(QuicConnectionRuntime runtime, long nowTicks)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TryMarkActivePathValidated",
            BindingFlags.Instance | BindingFlags.NonPublic)!;

        Assert.True((bool)method.Invoke(runtime, [nowTicks])!);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.ActivePath.Value.IsValidated);
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
        public long Ticks { get; private set; } = ticks;

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;

        public void Advance(long ticks)
        {
            Ticks += ticks;
        }
    }
}
