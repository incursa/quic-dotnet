using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0106")]
public sealed class REQ_QUIC_CRT_0106
{
    private static readonly byte[] HandshakeDestinationConnectionId = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];
    private static readonly byte[] HandshakeSourceConnectionId = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverTranscriptCompletionAndPeerTransportParameterCommitUpdateTheRuntimePhase()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTransportParameters peerTransportParameters = new()
        {
            DisableActiveMigration = true,
        };

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                    HandshakeMessageLength: 48,
                    SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                    TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                    TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
                    HandshakeMessageLength: 48,
                    TransportParameters: peerTransportParameters,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 10).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)),
            nowTicks: 10).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)),
            nowTicks: 10).StateChanged);
        Assert.True(runtime.TlsState.PeerCertificatePolicyAccepted);
        Assert.False(runtime.TlsState.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.False(runtime.TlsState.CanEmitPeerHandshakeTranscriptCompleted());

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed)),
            nowTicks: 10).StateChanged);

        Assert.False(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.TlsState.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.False(runtime.TlsState.CanEmitPeerHandshakeTranscriptCompleted());

        Assert.False(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: peerTransportParameters)),
            nowTicks: 10).StateChanged);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsPeerHandshakeTranscriptCompletionBeforeTheBridgeGateOpens()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)),
            nowTicks: 10);

        Assert.False(result.StateChanged);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, runtime.TlsState.HandshakeTranscriptPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverHandshakeKeyDiscardFlowsThroughTheRuntimeAndClearsHandshakeSendState()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 10).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 10).StateChanged);

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 7,
            PayloadBytes: 128,
            SentAtMicros: 0,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake)));

        Assert.Single(runtime.SendRuntime.SentPackets);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysDiscarded,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.False(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.Handshake, out _));
        Assert.Empty(runtime.SendRuntime.SentPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeExecutesTheDeterministicHandshakeSmokePathThroughPeerParameterStaging()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionPathIdentity path = runtime.ActivePath!.Value.Identity;
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        QuicConnectionTransitionResult bootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: localTransportParameters),
            nowTicks: 10);

        Assert.True(bootstrapResult.StateChanged);
        Assert.NotSame(localTransportParameters, runtime.TlsState.LocalTransportParameters);
        Assert.Equal(15UL, runtime.TlsState.LocalTransportParameters!.MaxIdleTimeout);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Empty(bootstrapResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        byte[] serverHelloTranscript = CreateServerHelloTranscript();

        QuicConnectionTransitionResult serverHelloResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                path,
                BuildProtectedHandshakePacket(material, serverHelloTranscript)),
            nowTicks: 11);

        Assert.True(serverHelloResult.StateChanged);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, runtime.TlsState.HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, runtime.TlsState.HandshakeTranscriptPhase);
        Assert.False(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.Null(runtime.TlsState.PeerTransportParameters);
        Assert.Null(runtime.TlsState.StagedPeerTransportParameters);
        Assert.Equal(0, runtime.TlsState.HandshakeIngressCryptoBuffer.BufferedBytes);
        Assert.False(runtime.TlsState.CanCommitPeerTransportParameters(CreatePeerTransportParameters()));
        Assert.False(runtime.TlsState.CanEmitPeerHandshakeTranscriptCompleted());

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 7,
            PayloadBytes: 128,
            SentAtMicros: 0,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake)));
        Assert.Single(runtime.SendRuntime.SentPackets);

        QuicConnectionTransitionResult discardResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysDiscarded,
                    QuicTlsEncryptionLevel.Handshake)),
            nowTicks: 12);

        Assert.True(discardResult.StateChanged);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
        Assert.False(runtime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.Handshake, out _));
        Assert.Empty(runtime.SendRuntime.SentPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsTamperedHandshakePacketsWithoutAdvancingTheTranscript()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionPathIdentity path = runtime.ActivePath!.Value.Identity;
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10).StateChanged);

        byte[] peerTranscript = CreateClientHandshakeTranscript(CreatePeerTransportParameters());
        byte[] tamperedPeerPacket = BuildProtectedHandshakePacket(material, peerTranscript);
        tamperedPeerPacket[^1] ^= 0x80;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                path,
                tamperedPeerPacket),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        Assert.False(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0, runtime.TlsState.HandshakeIngressCryptoBuffer.BufferedBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesDeterministicHandshakeTranscriptThroughTheExistingTlsReducer()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10).StateChanged);

        byte[] serverHelloTranscript = CreateServerHelloTranscript();

        QuicConnectionTransitionResult serverHelloResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                BuildProtectedHandshakePacket(
                    material,
                    serverHelloTranscript)),
            nowTicks: 11);

        Assert.True(serverHelloResult.StateChanged);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, runtime.TlsState.HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, runtime.TlsState.HandshakeTranscriptPhase);
        Assert.False(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.Null(runtime.TlsState.PeerTransportParameters);
        Assert.Null(runtime.TlsState.StagedPeerTransportParameters);
        Assert.Equal(0, runtime.TlsState.HandshakeIngressCryptoBuffer.BufferedBytes);
        Assert.False(runtime.TlsState.CanCommitPeerTransportParameters(CreatePeerTransportParameters()));
        Assert.False(runtime.TlsState.CanEmitPeerHandshakeTranscriptCompleted());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeAccumulatesFragmentedHandshakeCryptoAcrossMultiplePacketsBeforeStaging()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10).StateChanged);

        byte[] serverHelloTranscript = CreateServerHelloTranscript();

        byte[] firstPacket = BuildProtectedHandshakePacket(material, serverHelloTranscript.AsSpan(0, 5), cryptoOffset: 0);
        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                firstPacket),
            nowTicks: 11);

        Assert.True(firstResult.StateChanged);
        Assert.False(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.Null(runtime.TlsState.PeerTransportParameters);
        Assert.Null(runtime.TlsState.StagedPeerTransportParameters);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, runtime.TlsState.HandshakeTranscriptPhase);

        byte[] secondPacket = BuildProtectedHandshakePacket(material, serverHelloTranscript.AsSpan(5), cryptoOffset: 5);
        QuicConnectionTransitionResult secondResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 12,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                secondPacket),
            nowTicks: 12);

        Assert.True(secondResult.StateChanged);
        Assert.False(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, runtime.TlsState.HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, runtime.TlsState.HandshakeTranscriptPhase);
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Equal(0, runtime.TlsState.HandshakeIngressCryptoBuffer.BufferedBytes);
        Assert.Null(runtime.TlsState.PeerTransportParameters);
        Assert.Null(runtime.TlsState.StagedPeerTransportParameters);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedPeerHandshakeBlobRoutesFatalAlertThroughTheRuntimeCoordinator()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 9,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 9).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10).StateChanged);

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            CreateMalformedHandshakeTranscriptBytes(),
            cryptoPayloadOffset: 0,
            material,
            out byte[] malformedHandshakePacket));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                malformedHandshakePacket),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TlsState.FatalAlertCode);
        Assert.Equal("TLS alert 50.", runtime.TlsState.FatalAlertDescription);
        Assert.True(runtime.TlsState.IsTerminal);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, runtime.TlsState.HandshakeTranscriptPhase);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        QuicConnectionRuntime runtime = new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(HandshakeDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(HandshakeSourceConnectionId));
        return runtime;
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[1200]),
            nowTicks: 0).StateChanged);

        return runtime;
    }

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                IPv6Port = 8443,
                ConnectionId = [0x10, 0x11],
                StatelessResetToken = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F],
            },
            ActiveConnectionIdLimit = 4,
        };
    }

    private static byte[] CreateFormattedTransportParameters(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            encodedTransportParameters,
            out int bytesWritten));

        return encodedTransportParameters[..bytesWritten];
    }

    private static byte[] CreateEncryptedExtensionsTranscript(ReadOnlySpan<byte> encodedTransportParameters)
    {
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parameters));

        byte[] transcript = new byte[512];
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
            parameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int bytesWritten));

        Array.Resize(ref transcript, bytesWritten);
        return transcript;
    }

    private static byte[] CreateClientHandshakeTranscript(QuicTransportParameters transportParameters)
    {
        byte[] serverHello = CreateServerHelloTranscript();
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(
            CreateFormattedTransportParameters(transportParameters, QuicTransportParameterRole.Server));

        byte[] transcript = new byte[serverHello.Length + encryptedExtensions.Length];
        serverHello.CopyTo(transcript.AsSpan(0, serverHello.Length));
        encryptedExtensions.CopyTo(transcript.AsSpan(serverHello.Length));
        return transcript;
    }

    private static byte[] CreateServerHelloTranscript()
    {
        byte[] keyShare = CreateServerKeyShare();
        int extensionsLength = 6 + 4 + 2 + 2 + keyShare.Length;
        byte[] body = new byte[40 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        CreateSequentialBytes(0x40, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;

        body[index++] = 0;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256);
        index += 2;
        body[index++] = 0x00;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;

        WriteUInt16(body.AsSpan(index, 2), 0x002b);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), 0x0304);
        index += 2;

        WriteUInt16(body.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)(2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsNamedGroup.Secp256r1);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)keyShare.Length);
        index += 2;
        keyShare.CopyTo(body.AsSpan(index, keyShare.Length));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
    }

    private static byte[] CreateMalformedHandshakeTranscriptBytes()
    {
        return
        [
            0x08, 0x00, 0x00, 0x03,
            0x00, 0x02, 0x12,
        ];
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), body.Length);
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    private static void WriteUInt16(Span<byte> destination, ushort value)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, value);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }

    private static byte[] BuildProtectedHandshakePacket(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoOffset = 0)
    {
        QuicHandshakeFlowCoordinator coordinator = new(
            HandshakeDestinationConnectionId,
            HandshakeSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoOffset,
            material,
            out byte[] protectedPacket));
        return protectedPacket;
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

    private static byte[] CreateServerKeyShare()
    {
        using ECDiffieHellman serverKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        serverKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(0x02),
        });

        ECParameters parameters = serverKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[1 + (2 * 32)];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
