namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0005")]
public sealed class REQ_QUIC_RFC9000_S9P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildOutboundNewTokenPayload_WritesANewTokenFrame()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        byte[] token =
        [
            0x10, 0x20, 0x30, 0x40,
        ];

        Assert.True(runtime.TryBuildOutboundNewTokenPayload(token, out byte[] payload));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(payload, out QuicNewTokenFrame frame, out int bytesConsumed));
        Assert.Equal(6, bytesConsumed);
        Assert.Equal(0x07, payload[0]);
        Assert.True(frame.Token.SequenceEqual(token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryBuildOutboundNewTokenPayload_RejectsEmptyTokens()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();

        Assert.False(runtime.TryBuildOutboundNewTokenPayload(Array.Empty<byte>(), out byte[] payload));
        Assert.Empty(payload);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerValidationOfANewClientAddressEmitsANewTokenForTheValidatedPath()
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

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(validatedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(validatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == validatedPath
            && !promote.RestoreSavedState);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == validatedPath);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidationBeforeTheRuntimeIsActiveDefersNewTokenEmissionUntilOneRttSendMaterialExists()
    {
        byte[] localHandshakePrivateKey = new byte[32];
        localHandshakePrivateKey[^1] = 0x11;

        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(QuicS9P3TokenEmissionTestSupport.InitialDestinationConnectionId));

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

        Assert.DoesNotContain(validationResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);

        QuicTransportParameters peerTransportParameters = new()
        {
            MaxIdleTimeout = 21,
            OriginalDestinationConnectionId = [0x0A, 0x0B, 0x0C],
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
        };

        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ClientHello,
            HandshakeMessageLength: 1,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TransportParameters: peerTransportParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 1,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(runtime.TlsState.TryMarkPeerFinishedVerified());
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: QuicS9P3TokenEmissionTestSupport.CreateOneRttMaterial())));
        Assert.True(runtime.TlsState.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            EncryptionLevel: QuicTlsEncryptionLevel.OneRtt)));

        QuicConnectionTransitionResult activationResult = runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 40),
            nowTicks: 40);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Contains(activationResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == validatedPath);
    }
}
