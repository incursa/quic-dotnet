namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0007">Subsequent packets sent in the same packet number space MUST increase the packet number by at least one.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0007")]
public sealed class REQ_QUIC_RFC9000_S12P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketNumbersIncreaseByAtLeastOneInEachSpace()
    {
        byte[] initialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] initialSourceConnectionId =
        [
            0x01, 0x02, 0x03, 0x04,
        ];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDcid,
            out QuicInitialPacketProtection initialProtection));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        QuicHandshakeFlowCoordinator initialCoordinator = new(initialDcid, initialSourceConnectionId);
        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20),
            cryptoPayloadOffset: 0,
            initialProtection,
            out ulong firstInitialPacketNumber,
            out _));
        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x20, 20),
            cryptoPayloadOffset: 20,
            initialProtection,
            out ulong secondInitialPacketNumber,
            out _));

        byte[] handshakeDestinationConnectionId =
        [
            0x11, 0x12, 0x13, 0x14,
        ];
        byte[] handshakeSourceConnectionId =
        [
            0x21, 0x22, 0x23, 0x24,
        ];
        QuicHandshakeFlowCoordinator handshakeCoordinator = new(
            handshakeDestinationConnectionId,
            handshakeSourceConnectionId);
        Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x30, 20),
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong firstHandshakePacketNumber,
            out _));
        Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x40, 20),
            cryptoPayloadOffset: 20,
            handshakeMaterial,
            out ulong secondHandshakePacketNumber,
            out _));

        byte[] applicationDestinationConnectionId =
        [
            0x31, 0x32, 0x33, 0x34,
        ];
        byte[] applicationSourceConnectionId =
        [
            0x41, 0x42, 0x43, 0x44,
        ];
        QuicHandshakeFlowCoordinator applicationCoordinator = new(
            applicationDestinationConnectionId,
            applicationSourceConnectionId);
        Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            applicationMaterial,
            out ulong firstApplicationPacketNumber,
            out _));
        Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            applicationMaterial,
            out ulong secondApplicationPacketNumber,
            out _));

        Assert.Equal(0UL, firstInitialPacketNumber);
        Assert.Equal(1UL, secondInitialPacketNumber);
        Assert.Equal(0UL, firstHandshakePacketNumber);
        Assert.Equal(1UL, secondHandshakePacketNumber);
        Assert.Equal(0UL, firstApplicationPacketNumber);
        Assert.Equal(1UL, secondApplicationPacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryTimerExpired_RebuiltCryptoProbesAdvancePacketNumbersInBothSpaces()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-130535069-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-97980691c769433991df20c7c73aa52d.qlog
        // The captured connection-4 qlog showed repeated client Initial and Handshake retransmissions
        // with identical protected bytes. Recovery probes must instead advance the packet number in
        // each packet number space when rebuilding the lost CRYPTO packets.
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

        ulong originalInitialPacketNumber = Assert.Single(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial).PacketNumber;

        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        byte[] handshakeCrypto = QuicS12P3TestSupport.CreateSequentialBytes(0x90, 24);
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
        ulong originalHandshakePacketNumber = Assert.Single(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake).PacketNumber;

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
        Assert.True(TrySplitCoalescedDatagram(
            coalescedProbeEffect.Datagram,
            out ReadOnlyMemory<byte> initialPacket,
            out ReadOnlyMemory<byte> handshakePacket));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection));
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryOpenOutboundInitialPacket(
            initialPacket.Span,
            initialProtection,
            out byte[] openedInitialPacket,
            out int initialPayloadOffset,
            out _));
        Assert.True(coordinator.TryOpenHandshakePacket(
            handshakePacket.Span,
            handshakeMaterial,
            out byte[] openedHandshakePacket,
            out int handshakePayloadOffset,
            out _));

        ulong rebuiltInitialPacketNumber = ReadLongHeaderPacketNumber(openedInitialPacket, initialPayloadOffset);
        ulong rebuiltHandshakePacketNumber = ReadLongHeaderPacketNumber(openedHandshakePacket, handshakePayloadOffset);

        Assert.True(rebuiltInitialPacketNumber > originalInitialPacketNumber);
        Assert.True(rebuiltHandshakePacketNumber > originalHandshakePacketNumber);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RecoveryTimerExpired_RebuiltApplicationProbeAdvancesThePacketNumberForLostStreamData()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-145606434-client-chrome\
        //   live-server-qlog\d986c4d82a3fa16a.sqlog
        // The stalled multiconnect connection reached quic-go with a zero-length open marker and a
        // FIN-only close at final offset 36, while the missing request-bytes packet never repaired
        // the stream. Application-space PTO repair must therefore rebuild the request packet as a
        // fresh 1-RTT packet with a strictly larger packet number instead of replaying cached bytes.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];
        QuicS12P3ApplicationRecoveryTestSupport.InstallLocalDispatcher(runtime, outboundEffects);
        QuicS12P3ApplicationRecoveryTestSupport.PrimeApplicationPto(runtime, outboundEffects);

        byte[] requestPayload = System.Text.Encoding.ASCII.GetBytes("GET /arctic-exhilarated-lumberjack\r\n");
        (QuicStream stream, QuicConnectionSendDatagramEffect originalEffect) =
            await QuicS12P3ApplicationRecoveryTestSupport.OpenStreamAndCaptureRequestPacketAsync(
                runtime,
                outboundEffects,
                requestPayload);
        try
        {
            ulong streamId = (ulong)stream.Id;
            ulong originalPacketNumber = QuicS12P3ApplicationRecoveryTestSupport.ReadApplicationPacketNumber(
                runtime,
                originalEffect.Datagram,
                out QuicStreamFrame originalFrame,
                out bool keyPhase);

            Assert.False(keyPhase);
            Assert.Equal(streamId, originalFrame.StreamId.Value);
            Assert.Equal(0UL, originalFrame.Offset);
            Assert.False(originalFrame.IsFin);
            Assert.True(originalFrame.StreamData.SequenceEqual(requestPayload));

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

            QuicConnectionSendDatagramEffect applicationProbeEffect =
                QuicS12P3ApplicationRecoveryTestSupport.FindApplicationProbe(
                    runtime,
                    timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
                    streamId,
                    (ulong)requestPayload.Length,
                    requireFin: false);
            ulong rebuiltPacketNumber = QuicS12P3ApplicationRecoveryTestSupport.ReadApplicationPacketNumber(
                runtime,
                applicationProbeEffect.Datagram,
                out QuicStreamFrame probeFrame,
                out keyPhase);

            Assert.False(keyPhase);
            Assert.True(rebuiltPacketNumber > originalPacketNumber);
            Assert.Equal(streamId, probeFrame.StreamId.Value);
            Assert.Equal(0UL, probeFrame.Offset);
            Assert.False(probeFrame.IsFin);
            Assert.True(
                probeFrame.StreamData.SequenceEqual(requestPayload),
                "The rebuilt application probe must preserve the original HTTP/0.9 request bytes.");
        }
        finally
        {
            await stream.DisposeAsync();
        }
    }

    private static bool TrySplitCoalescedDatagram(
        ReadOnlyMemory<byte> datagram,
        out ReadOnlyMemory<byte> initialPacket,
        out ReadOnlyMemory<byte> handshakePacket)
    {
        initialPacket = default;
        handshakePacket = default;

        if (!QuicPacketParser.TryGetPacketLength(datagram.Span, out int initialPacketLength))
        {
            return false;
        }

        initialPacket = datagram[..initialPacketLength];
        handshakePacket = datagram[initialPacketLength..];
        return handshakePacket.Length > 0;
    }

    private static ulong ReadLongHeaderPacketNumber(byte[] openedPacket, int payloadOffset)
    {
        return QuicS17P1TestSupport.ReadPacketNumber(openedPacket.AsSpan(payloadOffset - sizeof(uint), sizeof(uint)));
    }
}

internal static class QuicS12P3ApplicationRecoveryTestSupport
{
    internal static void InstallLocalDispatcher(
        QuicConnectionRuntime runtime,
        List<QuicConnectionEffect> outboundEffects)
    {
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });
    }

    internal static void PrimeApplicationPto(
        QuicConnectionRuntime runtime,
        List<QuicConnectionEffect> outboundEffects)
    {
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath.Value.Identity,
                new byte[1280]),
            nowTicks: 10).StateChanged);
        outboundEffects.Clear();
    }

    internal static async Task<(QuicStream Stream, QuicConnectionSendDatagramEffect OriginalEffect)>
        OpenStreamAndCaptureRequestPacketAsync(
            QuicConnectionRuntime runtime,
            List<QuicConnectionEffect> outboundEffects,
            byte[] requestPayload)
    {
        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        await stream.WriteAsync(requestPayload, 0, requestPayload.Length);
        return (
            stream,
            Assert.Single(outboundEffects.OfType<QuicConnectionSendDatagramEffect>()));
    }

    internal static QuicConnectionSendDatagramEffect FindApplicationProbe(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        ulong expectedStreamId,
        ulong expectedFinalSize,
        bool requireFin)
    {
        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            _ = ReadApplicationPacketNumber(
                runtime,
                sendEffect.Datagram,
                out QuicStreamFrame frame,
                out _);

            if (frame.StreamId.Value == expectedStreamId
                && frame.IsFin == requireFin
                && frame.Offset + (ulong)frame.StreamDataLength == expectedFinalSize)
            {
                return sendEffect;
            }
        }

        Assert.Fail("No application PTO probe carried the expected stream payload.");
        return default!;
    }

    internal static ulong ReadApplicationPacketNumber(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        out QuicStreamFrame frame,
        out bool keyPhase)
    {
        frame = default;
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out keyPhase));

        ulong packetNumber = QuicS17P1TestSupport.ReadPacketNumber(
            openedPacket.AsSpan(payloadOffset - sizeof(uint), sizeof(uint)));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        int frameOffset = 0;
        while (frameOffset < payload.Length && payload[frameOffset] == 0)
        {
            frameOffset++;
        }

        Assert.True(
            frameOffset < payload.Length
            && QuicStreamParser.TryParseStreamFrame(payload[frameOffset..], out frame),
            "Expected the application packet payload to start with a STREAM frame after optional padding.");
        return packetNumber;
    }
}
