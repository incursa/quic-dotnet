using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0103")]
public sealed class REQ_QUIC_CRT_0103
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TlsBridgeStateSnapshotsTransportParametersAndTracksKeyLifecycleOutputs()
    {
        QuicTransportParameters localParameters = new()
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };

        QuicTransportParameters peerSeedParameters = new()
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

        Span<byte> encodedPeerParameters = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            peerSeedParameters,
            QuicTransportParameterRole.Server,
            encodedPeerParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedPeerParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedPeerParameters));

        QuicTransportTlsBridgeState bridge = new();

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: localParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
            HandshakeMessageLength: 48,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: 48,
            TransportParameters: parsedPeerParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.False(bridge.PeerTransportParametersCommitted);
        Assert.False(bridge.PeerHandshakeTranscriptCompleted);
        Assert.False(bridge.CanCommitPeerTransportParameters(parsedPeerParameters));
        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)));
        Assert.True(bridge.PeerCertificatePolicyAccepted);
        Assert.False(bridge.CanCommitPeerTransportParameters(parsedPeerParameters));
        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.False(bridge.PeerTransportParametersCommitted);
        Assert.False(bridge.PeerHandshakeTranscriptCompleted);
        Assert.False(bridge.CanCommitPeerTransportParameters(parsedPeerParameters));
        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: CreateHandshakeMaterial(0x11))));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: CreateHandshakeMaterial(0x21))));
        Assert.False(bridge.CanCommitPeerTransportParameters(parsedPeerParameters));
        Assert.False(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(bridge.CanCommitPeerTransportParameters(parsedPeerParameters));
        Assert.True(bridge.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: parsedPeerParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Initial)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeyUpdateInstalled,
            KeyPhase: 2)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysDiscarded,
            QuicTlsEncryptionLevel.Initial)));

        localParameters.InitialSourceConnectionId![0] = 0xFF;
        parsedPeerParameters.InitialSourceConnectionId![0] = 0xEE;
        parsedPeerParameters.PreferredAddress!.ConnectionId[0] = 0x99;
        parsedPeerParameters.PreferredAddress.StatelessResetToken[0] = 0x98;

        Assert.NotSame(localParameters, bridge.LocalTransportParameters);
        Assert.NotSame(parsedPeerParameters, bridge.PeerTransportParameters);
        Assert.Equal(15UL, bridge.LocalTransportParameters!.MaxIdleTimeout);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, bridge.LocalTransportParameters.InitialSourceConnectionId);
        Assert.Equal(30UL, bridge.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(bridge.PeerTransportParametersCommitted);
        Assert.False(bridge.InitialKeysAvailable);
        Assert.True(bridge.HandshakeKeysAvailable);
        Assert.NotNull(bridge.HandshakeOpenPacketProtectionMaterial);
        Assert.NotNull(bridge.HandshakeProtectPacketProtectionMaterial);
        Assert.True(bridge.OneRttKeysAvailable);
        Assert.True(bridge.PeerHandshakeTranscriptCompleted);
        Assert.True(bridge.PeerFinishedVerified);
        Assert.True(bridge.KeyUpdateInstalled);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.Equal(2UL, bridge.CurrentOneRttKeyPhase);
        Assert.True(bridge.HasAnyAvailableKeys);
        Assert.False(bridge.IsTerminal);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, bridge.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(new byte[] { 0x10, 0x11 }, bridge.PeerTransportParameters.PreferredAddress!.ConnectionId);
        Assert.Equal(new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F }, bridge.PeerTransportParameters.PreferredAddress.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProhibitedKeyUpdatesMarkTheBridgeTerminal()
    {
        QuicTransportTlsBridgeState bridge = new();

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation)));

        Assert.True(bridge.IsTerminal);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, bridge.FatalAlertCode);
        Assert.Equal("TLS KeyUpdate was prohibited.", bridge.FatalAlertDescription);
        Assert.False(bridge.HasAnyAvailableKeys);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverConsumesBufferedInboundCryptoBytes()
    {
        QuicTlsTransportBridgeDriver driver = new();
        byte[] inboundCrypto = [0x10, 0x11, 0x12, 0x13];

        Assert.True(driver.TryBufferIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            offset: 0,
            inboundCrypto,
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);

        inboundCrypto[0] = 0xFF;

        Span<byte> dequeuedCrypto = stackalloc byte[4];
        Assert.True(driver.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            dequeuedCrypto,
            out int bytesWritten));

        Assert.Equal(4, bytesWritten);
        Assert.True(new byte[] { 0x10, 0x11, 0x12, 0x13 }.AsSpan().SequenceEqual(dequeuedCrypto[..bytesWritten]));
        Assert.False(driver.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            dequeuedCrypto,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverQueuesOutboundCryptoBytes()
    {
        QuicTlsTransportBridgeDriver driver = new();
        byte[] outboundCrypto = [0x20, 0x21, 0x22];

        Assert.True(driver.TryBufferOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            offset: 0,
            outboundCrypto,
            out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);

        outboundCrypto[0] = 0xEE;

        Span<byte> dequeuedCrypto = stackalloc byte[3];
        Assert.True(driver.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            dequeuedCrypto,
            out int bytesWritten));

        Assert.Equal(3, bytesWritten);
        Assert.True(new byte[] { 0x20, 0x21, 0x22 }.AsSpan().SequenceEqual(dequeuedCrypto[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverConsumesDeterministicHandshakeTranscriptBytesIncrementally()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();
        byte[] peerHandshakeTranscript = CreateClientHandshakeTranscript(peerParameters);

        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(localParameters));

        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            peerHandshakeTranscript[..5]);

        Assert.Empty(firstUpdates);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, driver.State.HandshakeTranscriptPhase);
        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            peerHandshakeTranscript[5..]);

        Assert.Equal(5, updates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, updates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, updates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, updates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, updates[0].TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, updates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, updates[3].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[3].EncryptionLevel);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[4].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, updates[4].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, updates[4].TranscriptPhase);
        QuicTransportParameters? stagedTransportParameters = updates[4].TransportParameters;
        Assert.NotNull(stagedTransportParameters);
        Assert.Equal(30UL, stagedTransportParameters!.MaxIdleTimeout);
        Assert.True(stagedTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, stagedTransportParameters.InitialSourceConnectionId);
        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.NotNull(driver.State.HandshakeOpenPacketProtectionMaterial);
        Assert.NotNull(driver.State.HandshakeProtectPacketProtectionMaterial);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, driver.State.HandshakeTranscriptPhase);
        Assert.NotNull(driver.State.StagedPeerTransportParameters);
        Assert.NotSame(peerParameters, driver.State.StagedPeerTransportParameters);
        Assert.Equal(30UL, driver.State.StagedPeerTransportParameters!.MaxIdleTimeout);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, driver.State.StagedPeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(0, driver.State.HandshakeIngressCryptoBuffer.BufferedBytes);

        Assert.Empty(driver.CommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        Span<byte> drainedInboundCrypto = stackalloc byte[1];
        Assert.False(driver.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            drainedInboundCrypto,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BridgeDriverRejectsRepeatedHandshakeTranscriptProgressionDeterministically()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();
        byte[] peerHandshakeTranscript = CreateClientHandshakeTranscript(peerParameters);

        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(localParameters));

        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            peerHandshakeTranscript);

        Assert.Equal(5, firstUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, firstUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, firstUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, firstUpdates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, firstUpdates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, firstUpdates[0].TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, firstUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, firstUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, firstUpdates[3].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, firstUpdates[3].EncryptionLevel);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, firstUpdates[4].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, firstUpdates[4].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, firstUpdates[4].TranscriptPhase);
        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        IReadOnlyList<QuicTlsStateUpdate> repeatedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            peerHandshakeTranscript);

        Assert.Single(repeatedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, repeatedUpdates[0].Kind);
        Assert.Equal((ushort)0x0032, repeatedUpdates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BridgeDriverDoesNotCommitRawTransportParameterBlobsByConstruction()
    {
        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(CreateBootstrapLocalTransportParameters()));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateFormattedTransportParameters(
                CreatePeerTransportParameters(),
                QuicTransportParameterRole.Server));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.IsTerminal);
        Assert.Equal(QuicTlsTranscriptPhase.Failed, driver.State.HandshakeTranscriptPhase);
        Assert.Empty(driver.CommitPeerTransportParameters(CreatePeerTransportParameters()));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverEmitsCommittedPeerTransportParametersOnlyAfterTranscriptCompletion()
    {
        QuicTransportParameters peerParameters = new()
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
        };

        QuicTlsTransportBridgeDriver driver = new();
        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage,
            QuicTlsHandshakeMessageType.ServerHello,
            handshakeMessageLength: 48,
            selectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            transcriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256);
        Assert.Single(serverHelloUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, serverHelloUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, serverHelloUpdates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, serverHelloUpdates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, serverHelloUpdates[0].TranscriptHashAlgorithm);

        IReadOnlyList<QuicTlsStateUpdate> stageUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            QuicTlsHandshakeMessageType.EncryptedExtensions,
            handshakeMessageLength: 48,
            transportParameters: peerParameters);
        Assert.Single(stageUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, stageUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, stageUpdates[0].HandshakeMessageType);
        Assert.Equal((uint)48, stageUpdates[0].HandshakeMessageLength);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, stageUpdates[0].TranscriptPhase);
        Assert.True(stageUpdates[0].TransportParameters is not null);

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            QuicTlsHandshakeMessageType.CertificateVerify,
            handshakeMessageLength: 48);
        Assert.Single(certificateVerifyUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, certificateVerifyUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.CertificateVerify, certificateVerifyUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, certificateVerifyUpdates[0].TranscriptPhase);
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)));
        Assert.True(driver.State.PeerCertificateVerifyVerified);
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)));
        Assert.True(driver.State.PeerCertificatePolicyAccepted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        IReadOnlyList<QuicTlsStateUpdate> completedUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.Completed,
            QuicTlsHandshakeMessageType.Finished,
            handshakeMessageLength: 48);

        Assert.Single(completedUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, completedUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, completedUpdates[0].HandshakeMessageType);
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)));
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.CommitPeerTransportParameters(peerParameters);

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersCommitted, updates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        QuicConnectionRuntime runtime = CreateRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                serverHelloUpdates[0]),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                stageUpdates[0]),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                certificateVerifyUpdates[0]),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                completedUpdates[0]),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)),
            nowTicks: 11).StateChanged);

        peerParameters.InitialSourceConnectionId![0] = 0xFF;

        Assert.NotSame(peerParameters, driver.State.PeerTransportParameters);
        Assert.Equal(30UL, driver.State.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(driver.State.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, driver.State.PeerTransportParameters.InitialSourceConnectionId);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration));
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));
        Assert.Equal(30_000UL, runtime.PeerMaxIdleTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverStartHandshakePublishesLocalTransportParameters()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();

        QuicTlsTransportBridgeDriver driver = new();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.StartHandshake(localParameters);

        QuicTlsStateUpdate localTransportParametersUpdate = Assert.Single(
            updates,
            update => update.Kind == QuicTlsUpdateKind.LocalTransportParametersReady);
        Assert.Same(localParameters, localTransportParametersUpdate.TransportParameters);
        Assert.NotSame(localParameters, driver.State.LocalTransportParameters);
        Assert.Equal(15UL, driver.State.LocalTransportParameters!.MaxIdleTimeout);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, driver.State.LocalTransportParameters.InitialSourceConnectionId);
        Assert.False(driver.State.HandshakeKeysAvailable);
        Assert.Equal(0, driver.State.HandshakeEgressCryptoBuffer.BufferedBytes);
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            stackalloc byte[1],
            out _,
            out _));

        localParameters.InitialSourceConnectionId![0] = 0xFF;

        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, driver.State.LocalTransportParameters.InitialSourceConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesHandshakeBootstrapUpdatesThroughTheExistingTlsReducer()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult bootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: localParameters),
            nowTicks: 10);

        Assert.True(bootstrapResult.StateChanged);
        Assert.Equal(QuicConnectionEventKind.HandshakeBootstrapRequested, bootstrapResult.EventKind);
        Assert.NotSame(localParameters, runtime.TlsState.LocalTransportParameters);
        Assert.Equal(15UL, runtime.TlsState.LocalTransportParameters!.MaxIdleTimeout);
        Assert.Equal(15_000UL, runtime.LocalMaxIdleTimeoutMicros);
        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.Equal(0, runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
                    HandshakeMessageLength: 48,
                    SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
                    TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
                    TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage)),
            nowTicks: 11).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
                    HandshakeMessageLength: 48,
                    TransportParameters: peerParameters,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 11).StateChanged);

        Assert.False(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.False(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.TlsState.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(runtime.TlsState.CanEmitPeerHandshakeTranscriptCompleted());

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)),
            nowTicks: 11).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)),
            nowTicks: 11).StateChanged);
        Assert.False(runtime.TlsState.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(runtime.TlsState.CanEmitPeerHandshakeTranscriptCompleted());

        Assert.False(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PeerTransportParametersCommitted,
                    TransportParameters: peerParameters)),
            nowTicks: 11).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.TranscriptProgressed,
                    HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
                    HandshakeMessageLength: 48,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed)),
            nowTicks: 11).StateChanged);

        QuicConnectionTransitionResult peerFinishedVerifiedResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 11);

        Assert.True(peerFinishedVerifiedResult.StateChanged);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));

        QuicConnectionTransitionResult peerHandshakeTranscriptCompletedResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 11,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)),
            nowTicks: 11);

        Assert.True(peerHandshakeTranscriptCompletedResult.StateChanged);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakeBootstrapRejectsRepeatedRequests()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult firstBootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 10,
                LocalTransportParameters: CreateBootstrapLocalTransportParameters()),
            nowTicks: 10);

        QuicConnectionTransitionResult repeatedBootstrapResult = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 11,
                LocalTransportParameters: new QuicTransportParameters
                {
                    MaxIdleTimeout = 20,
                }),
            nowTicks: 11);

        Assert.True(firstBootstrapResult.StateChanged);
        Assert.False(repeatedBootstrapResult.StateChanged);
        Assert.Equal(15_000UL, runtime.LocalMaxIdleTimeoutMicros);
        Assert.NotNull(runtime.TlsState.LocalTransportParameters);
        Assert.Equal(15UL, runtime.TlsState.LocalTransportParameters!.MaxIdleTimeout);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakeBootstrapRejectsInvalidTransportParameters()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 12,
                LocalTransportParameters: null),
            nowTicks: 12);

        Assert.False(result.StateChanged);
        Assert.Equal(QuicConnectionEventKind.HandshakeBootstrapRequested, result.EventKind);
        Assert.Null(runtime.TlsState.LocalTransportParameters);
        Assert.Null(runtime.LocalMaxIdleTimeoutMicros);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverEmitsCommittedPeerTransportParametersAfterPeerFinishedVerification()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();

        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(localParameters));

        IReadOnlyList<QuicTlsStateUpdate> stageUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHandshakeTranscript(peerParameters));

        Assert.Equal(5, stageUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, stageUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, stageUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, stageUpdates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, stageUpdates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, stageUpdates[0].TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, stageUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, stageUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, stageUpdates[3].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, stageUpdates[3].EncryptionLevel);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, stageUpdates[4].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, stageUpdates[4].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, stageUpdates[4].TranscriptPhase);
        Assert.NotNull(stageUpdates[4].TransportParameters);
        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            QuicTlsHandshakeMessageType.CertificateVerify,
            handshakeMessageLength: 48);
        Assert.Single(certificateVerifyUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, certificateVerifyUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.CertificateVerify, certificateVerifyUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, certificateVerifyUpdates[0].TranscriptPhase);
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)));
        Assert.True(driver.State.PeerCertificateVerifyVerified);
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)));
        Assert.True(driver.State.PeerCertificatePolicyAccepted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        IReadOnlyList<QuicTlsStateUpdate> completedUpdates = driver.PublishTranscriptProgressed(
            QuicTlsTranscriptPhase.Completed,
            QuicTlsHandshakeMessageType.Finished,
            handshakeMessageLength: 48);
        Assert.Single(completedUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, completedUpdates[0].Kind);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, completedUpdates[0].TranscriptPhase);
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(driver.State.CanEmitPeerHandshakeTranscriptCompleted());
        Assert.True(driver.State.CanCommitPeerTransportParameters(peerParameters));

        IReadOnlyList<QuicTlsStateUpdate> commitUpdates = driver.CommitPeerTransportParameters(peerParameters);
        Assert.Single(commitUpdates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersCommitted, commitUpdates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersCommitted);
        Assert.True(driver.State.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)));
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(driver.State.CanEmitPeerHandshakeTranscriptCompleted());

        QuicConnectionRuntime runtime = CreateRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                stageUpdates[0]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                stageUpdates[1]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                stageUpdates[2]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                stageUpdates[3]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                stageUpdates[4]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                certificateVerifyUpdates[0]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                completedUpdates[0]),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)),
            nowTicks: 12).StateChanged);
        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.True(runtime.TransportFlags.HasFlag(QuicConnectionTransportState.PeerTransportParametersCommitted));
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 12,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted)),
            nowTicks: 12).StateChanged);

        Assert.True(runtime.TlsState.PeerTransportParametersCommitted);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeDriverEmitsKeyDiscardUpdates()
    {
        QuicTlsTransportBridgeDriver driver = new();
        QuicTlsPacketProtectionMaterial handshakeMaterial = CreateHandshakeMaterial(0x11);
        Assert.True(driver.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: handshakeMaterial)));

        IReadOnlyList<QuicTlsStateUpdate> availableUpdates = driver.PublishKeysAvailable(QuicTlsEncryptionLevel.Handshake);
        Assert.Single(availableUpdates);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.NotNull(driver.State.HandshakeOpenPacketProtectionMaterial);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.PublishKeyDiscard(QuicTlsEncryptionLevel.Handshake);
        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.KeysDiscarded, updates[0].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[0].EncryptionLevel);
        Assert.False(driver.State.HandshakeKeysAvailable);
        Assert.True(driver.State.OldKeysDiscarded);

        QuicConnectionRuntime runtime = CreateRuntime();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 20,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: handshakeMaterial)),
            nowTicks: 20).StateChanged);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 20,
                availableUpdates[0]),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 21,
                updates[0]),
            nowTicks: 21).StateChanged);

        Assert.False(runtime.TlsState.HandshakeKeysAvailable);
        Assert.True(runtime.TlsState.OldKeysDiscarded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FatalAlertBridgeUpdatesRouteThroughTheExistingRuntimeSeam()
    {
        QuicTlsTransportBridgeDriver driver = new();
        Assert.NotEmpty(driver.StartHandshake(CreateBootstrapLocalTransportParameters()));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateMalformedHandshakeTranscriptBytes());

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);

        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 40,
                updates[0]),
            nowTicks: 40);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal("TLS alert 50.", runtime.TerminalState?.Close.ReasonPhrase);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
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

    private static QuicTlsPacketProtectionMaterial CreateHandshakeMaterial(byte startValue)
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(startValue, 16),
            CreateSequentialBytes(unchecked((byte)(startValue + 0x10)), 12),
            CreateSequentialBytes(unchecked((byte)(startValue + 0x20)), 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        return material;
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
        QuicTransportParameters parameters = new();
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters,
            QuicTransportParameterRole.Client,
            out parameters));

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

    private static byte[] CreateMalformedHandshakeTranscriptBytes()
    {
        return [0x08, 0x00, 0x00, 0x03, 0x00, 0x02, 0x12];
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
