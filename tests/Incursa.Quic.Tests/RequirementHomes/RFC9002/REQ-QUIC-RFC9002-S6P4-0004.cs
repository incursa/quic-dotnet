namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P4-0004">Initial and Handshake secrets MUST be discarded as soon as Handshake and 1-RTT keys are proven to be available to both client and server.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P4-0004")]
public sealed class REQ_QUIC_RFC9002_S6P4_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAddFrame_DiscardOverflowFramesAsSoonAsReplacementKeysExist()
    {
        QuicCryptoBuffer buffer = new()
        {
            HandshakeComplete = true,
        };

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult bufferedResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, bufferedResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xAA]), out QuicCryptoBufferResult discardedResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, discardedResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4097, [0xBB]), out QuicCryptoBufferResult futureResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, futureResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRuntimeDiscardsInitialRecoveryStateAfterTheFirstSuccessfulHandshakePacket()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-182027795-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\server\qlog\6a002c060ffc5da0.sqlog
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-192025145-client-chrome\
        //   live simulator trace + server log
        // The stalled multiconnect path kept sending stale Initial+Handshake probes after
        // 1-RTT was already live. The first missing cleanup boundary was that the client
        // never discarded Initial recovery state after it successfully processed the peer's
        // first Handshake packet.
        using QuicCapturedInteropReplayTestSupport.CapturedInteropHandshakeScenario scenario =
            QuicCapturedInteropReplayTestSupport.CreateDeterministicQuicGoClientHandshakeScenario();

        QuicConnectionRuntime runtime = scenario.ClientRuntime;

        QuicConnectionTransitionResult initialResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerInitialPacket),
            nowTicks: 10);

        Assert.True(initialResult.StateChanged);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.False(runtime.TlsState.OldKeysDiscarded);

        SeedTrackedPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            packetNumber: 99,
            sentAtMicros: 9,
            QuicTlsEncryptionLevel.Initial);
        SeedTrackedPacket(
            runtime,
            QuicPacketNumberSpace.Handshake,
            packetNumber: 41,
            sentAtMicros: 10,
            QuicTlsEncryptionLevel.Handshake);

        QuicConnectionTransitionResult handshakeResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerHandshakePacket),
            nowTicks: 11);

        Assert.True(handshakeResult.StateChanged);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && key.PacketNumber == 99);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && key.PacketNumber == 41);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRuntimeDiscardsHandshakeRecoveryStateWhenHandshakeDoneConfirmsTheHandshake()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-182027795-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-b7d0662decde48a0bbd3ea68033bf1d8.qlog
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-192025145-client-chrome\
        //   live simulator trace + server log
        // After the request stream was already open on the stalled multiconnect connection,
        // the client still emitted Handshake probes instead of clearing the Handshake space
        // when HANDSHAKE_DONE confirmed the handshake.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);

        SeedTrackedPacket(
            runtime,
            QuicPacketNumberSpace.Handshake,
            packetNumber: 77,
            sentAtMicros: 7,
            QuicTlsEncryptionLevel.Handshake);
        SeedTrackedPacket(
            runtime,
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 78,
            sentAtMicros: 7,
            QuicTlsEncryptionLevel.OneRtt);

        QuicConnectionTransitionResult handshakeDoneResult =
            QuicPostHandshakeTicketTestSupport.ReceiveProtectedHandshakeDonePacket(runtime, observedAtTicks: 12);

        Assert.True(handshakeDoneResult.StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && key.PacketNumber == 77);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && key.PacketNumber == 78);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRuntimeDiscardsInitialRecoveryStateWhenPeerHandshakeTranscriptCompletes()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-205045193-server-nginx\
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt
        //   runner-logs\nginx_quic-go\handshakeloss\server\qlog\server-multiconnect-5486d3610f1c4d1ebffa979598d31d57.qlog
        // The narrowed server-role multiconnect replay advanced past Initial crypto starvation, but
        // connection 2 still received stale server Initial probes after quic-go installed 1-RTT keys
        // and dropped Initial keys. Peer transcript completion is the server-side safety boundary
        // that must clear leftover Initial recovery state if an earlier Handshake packet did not.
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(isServer: true),
            tlsRole: QuicTlsRole.Server);
        Assert.True(runtime.TrySetBootstrapOutboundPath(new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443)));

        SeedTrackedPacket(
            runtime,
            QuicPacketNumberSpace.Initial,
            packetNumber: 101,
            sentAtMicros: 11,
            QuicTlsEncryptionLevel.Initial);
        SeedTrackedPacket(
            runtime,
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 102,
            sentAtMicros: 12,
            QuicTlsEncryptionLevel.OneRtt);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 20),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && key.PacketNumber == 101);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && key.PacketNumber == 102);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAddFrame_ClosesWithBufferExceededBeforeReplacementKeysExist()
    {
        QuicCryptoBuffer buffer = new();

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult bufferedResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, bufferedResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xCC]), out QuicCryptoBufferResult overflowResult));
        Assert.Equal(QuicCryptoBufferResult.BufferExceeded, overflowResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAddFrame_TransitionsFromBufferingToDiscardingAtTheHandshakeCompleteBoundary()
    {
        QuicCryptoBuffer buffer = new()
        {
            HandshakeComplete = true,
        };

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4095]), out QuicCryptoBufferResult bufferedResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, bufferedResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4095, [0xDD]), out QuicCryptoBufferResult boundaryResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, boundaryResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xEE]), out QuicCryptoBufferResult overflowResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, overflowResult);
    }

    private static void SeedTrackedPacket(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong sentAtMicros,
        QuicTlsEncryptionLevel packetProtectionLevel)
    {
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            PayloadBytes: 1_200,
            SentAtMicros: sentAtMicros,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x01 },
            PacketProtectionLevel: packetProtectionLevel,
            CryptoMetadata: packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake
                ? new QuicConnectionCryptoSendMetadata(packetProtectionLevel)
                : null));
    }
}
