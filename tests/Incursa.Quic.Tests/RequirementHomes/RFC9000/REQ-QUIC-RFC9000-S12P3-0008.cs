namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0008">A QUIC endpoint MUST NOT reuse a packet number within the same packet number space in one connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0008")]
public sealed class REQ_QUIC_RFC9000_S12P3_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecoveryTimerExpired_DoesNotReusePacketNumbersForCoalescedCryptoProbes()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-130535069-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-97980691c769433991df20c7c73aa52d.qlog
        // The failing multiconnect connection repeated byte-for-byte identical Initial and Handshake
        // packets during PTO. This proof keeps the runtime from reusing packet numbers in either
        // packet number space when rebuilding those CRYPTO probes.
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

        byte[] handshakeCrypto = QuicS12P3TestSupport.CreateSequentialBytes(0xA0, 24);
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
        QuicConnectionSendDatagramEffect originalHandshakeEffect = Assert.Single(
            handshakeSendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
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
            out ReadOnlyMemory<byte> rebuiltInitialPacket,
            out ReadOnlyMemory<byte> rebuiltHandshakePacket));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection));
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryOpenOutboundInitialPacket(
            rebuiltInitialPacket.Span,
            initialProtection,
            out byte[] openedInitialPacket,
            out int initialPayloadOffset,
            out _));
        Assert.True(coordinator.TryOpenHandshakePacket(
            rebuiltHandshakePacket.Span,
            handshakeMaterial,
            out byte[] openedHandshakePacket,
            out int handshakePayloadOffset,
            out _));

        ulong rebuiltInitialPacketNumber = ReadLongHeaderPacketNumber(openedInitialPacket, initialPayloadOffset);
        ulong rebuiltHandshakePacketNumber = ReadLongHeaderPacketNumber(openedHandshakePacket, handshakePayloadOffset);

        Assert.NotEqual(originalInitialPacketNumber, rebuiltInitialPacketNumber);
        Assert.NotEqual(originalHandshakePacketNumber, rebuiltHandshakePacketNumber);
        Assert.False(
            originalHandshakeEffect.Datagram.Span.SequenceEqual(rebuiltHandshakePacket.Span),
            "The rebuilt Handshake probe must not reuse the original protected bytes.");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RecoveryTimerExpired_DoesNotReusePacketNumbersForApplicationStreamRepair()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-145606434-client-chrome\
        //   live-server-qlog\d986c4d82a3fa16a.sqlog
        // quic-go preserved the stalled multiconnect connection long enough to show that the client
        // kept probing without repairing the missing request-bytes packet. The rebuilt application
        // probe must therefore use a fresh packet number and fresh protected bytes.
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
                out _,
                out _);

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
                out bool keyPhase);

            Assert.False(keyPhase);
            Assert.NotEqual(originalPacketNumber, rebuiltPacketNumber);
            Assert.False(
                originalEffect.Datagram.Span.SequenceEqual(applicationProbeEffect.Datagram.Span),
                "The rebuilt application probe must not reuse the original protected bytes.");
            Assert.Equal(streamId, probeFrame.StreamId.Value);
            Assert.Equal(0UL, probeFrame.Offset);
            Assert.False(probeFrame.IsFin);
            Assert.True(probeFrame.StreamData.SequenceEqual(requestPayload));
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
