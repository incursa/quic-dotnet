// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S5-1-1-P8-S2-R01")]
public sealed class RFC9000_S5_1_1_P8_S2_R01
{
    private static readonly byte[] HandshakeDestinationConnectionId =
    [
        0x71, 0x72, 0x73,
    ];

    private static readonly byte[] LocalSourceConnectionId =
    [
        0x81, 0x82, 0x83, 0x84,
    ];

    private static readonly QuicConnectionPathIdentity ActivePath =
        new("203.0.113.220", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OpenOutboundStream_WhenPeerSelectsZeroLengthConnectionId_UsesZeroLengthDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = CreateActiveRuntime(peerInitialSourceConnectionId: []);

        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        QuicConnectionSendDatagramEffect send = await OpenStreamAndCaptureSendAsync(runtime);

        AssertApplicationDataDatagramOpensWithDestination(runtime, send.Datagram, ReadOnlyMemory<byte>.Empty);
        AssertApplicationDataDatagramDoesNotOpenWithDestination(runtime, send.Datagram, HandshakeDestinationConnectionId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task OpenOutboundStream_WhenPeerSelectsNonZeroConnectionId_UsesNonZeroDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = CreateActiveRuntime(
            peerInitialSourceConnectionId: HandshakeDestinationConnectionId);

        Assert.Equal(HandshakeDestinationConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());

        QuicConnectionSendDatagramEffect send = await OpenStreamAndCaptureSendAsync(runtime);

        AssertApplicationDataDatagramOpensWithDestination(runtime, send.Datagram, HandshakeDestinationConnectionId);
        AssertApplicationDataDatagramDoesNotOpenWithDestination(runtime, send.Datagram, ReadOnlyMemory<byte>.Empty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CurrentPeerDestinationConnectionId_WhenPeerZeroLengthModeHasPreferredAddress_StillUsesZeroLengthDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = CreateActiveRuntime(
            peerInitialSourceConnectionId: [],
            preferredAddress: new QuicPreferredAddress
            {
                IPv4Address =
                [
                    203, 0, 113, 221,
                ],
                IPv4Port = 9443,
                ConnectionId =
                [
                    0x91, 0x92, 0x93, 0x94,
                ],
                StatelessResetToken = QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0xA0),
            });

        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);
    }

    [Fact]
    [Requirement("RFC9000-S5-1-1-P8-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task OpenOutboundStreamFuzz_WhenPeerSelectsZeroLengthConnectionId_UsesZeroLengthDestinationConnectionId()
    {
        QuicStreamType[] streamTypes =
        [
            QuicStreamType.Bidirectional,
            QuicStreamType.Unidirectional,
        ];

        foreach (QuicStreamType streamType in streamTypes)
        {
            using QuicConnectionRuntime runtime = CreateActiveRuntime(peerInitialSourceConnectionId: []);

            Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

            QuicConnectionSendDatagramEffect send = await OpenStreamAndCaptureSendAsync(runtime, streamType);

            AssertApplicationDataDatagramOpensWithDestination(runtime, send.Datagram, ReadOnlyMemory<byte>.Empty);
            AssertApplicationDataDatagramDoesNotOpenWithDestination(runtime, send.Datagram, HandshakeDestinationConnectionId);
        }
    }

    private static QuicConnectionRuntime CreateActiveRuntime(
        ReadOnlySpan<byte> peerInitialSourceConnectionId,
        QuicPreferredAddress? preferredAddress = null)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(ActivePath);
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(HandshakeDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(LocalSourceConnectionId));

        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();
        peerTransportParameters.InitialSourceConnectionId = peerInitialSourceConnectionId.ToArray();
        peerTransportParameters.PreferredAddress = preferredAddress;
        CommitPeerTransportParametersThroughRuntimeAndSeedOneRttPacketProtectionMaterial(runtime, peerTransportParameters);

        return runtime;
    }

    private static void CommitPeerTransportParametersThroughRuntimeAndSeedOneRttPacketProtectionMaterial(
        QuicConnectionRuntime runtime,
        QuicTransportParameters peerTransportParameters)
    {
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                    HandshakeMessageLength: 48,
                    SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                    TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                    TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)),
            nowTicks: 0).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
                    HandshakeMessageLength: 48,
                    TransportParameters: peerTransportParameters,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 1).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 2,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 2).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 3,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)),
            nowTicks: 3).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 4,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)),
            nowTicks: 4).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 5,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed)),
            nowTicks: 5).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 6,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 6).StateChanged);

        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.NotNull(runtime.TlsState.PeerTransportParameters);

        using QuicConnectionRuntime materialRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 7,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    EncryptionLevel: QuicTlsEncryptionLevel.OneRtt)),
            nowTicks: 7).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 8,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: materialRuntime.TlsState.OneRttOpenPacketProtectionMaterial!.Value)),
            nowTicks: 8).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: materialRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    private static async Task<QuicConnectionSendDatagramEffect> OpenStreamAndCaptureSendAsync(
        QuicConnectionRuntime runtime,
        QuicStreamType streamType = QuicStreamType.Bidirectional)
    {
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(streamType);
        Assert.NotNull(stream);
        return Assert.Single(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
    }

    private static void AssertApplicationDataDatagramOpensWithDestination(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId)
    {
        Assert.True(TryOpenApplicationDataDatagram(
            runtime,
            datagram,
            destinationConnectionId,
            out _,
            out _,
            out _));
    }

    private static void AssertApplicationDataDatagramDoesNotOpenWithDestination(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId)
    {
        Assert.False(TryOpenApplicationDataDatagram(
            runtime,
            datagram,
            destinationConnectionId,
            out _,
            out _,
            out _));
    }

    private static bool TryOpenApplicationDataDatagram(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId);
        return coordinator.TryOpenProtectedApplicationDataPacket(
            datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out openedPacket,
            out payloadOffset,
            out payloadLength);
    }
}
