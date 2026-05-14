using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0112")]
public sealed class REQ_QUIC_CRT_0112
{
    private static readonly byte[] QuicKeyLabel = System.Text.Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = System.Text.Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicHpLabel = System.Text.Encoding.ASCII.GetBytes("quic hp");

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleKeySchedulePublishesServerHelloBeforeHandshakeKeys()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTlsCipherSuite[] selectedCipherSuites =
        [
            QuicTlsCipherSuite.TlsAes128GcmSha256,
            QuicTlsCipherSuite.TlsChacha20Poly1305Sha256,
        ];

        foreach (QuicTlsCipherSuite selectedCipherSuite in selectedCipherSuites)
        {
            QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server, selectedCipherSuite);
            byte[] clientHello = CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                cipherSuites: [(ushort)selectedCipherSuite]);

            progress.AppendCryptoBytes(0, clientHello);
            QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);
            Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, clientHelloStep.Kind);
            Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, clientHelloStep.TranscriptPhase);

            QuicTlsKeySchedule schedule = new(
                QuicTlsRole.Server,
                localHandshakePrivateKey,
                selectedCipherSuite: selectedCipherSuite);
            IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(clientHelloStep, localTransportParameters);

            Assert.True(updates.Count >= 4);
            Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[0].Kind);
            Assert.Equal(QuicTlsEncryptionLevel.Initial, updates[0].EncryptionLevel);
            Assert.Equal(0UL, updates[0].CryptoDataOffset);
            Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, updates[1].Kind);
            Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, updates[2].Kind);
            Assert.Equal(QuicTlsUpdateKind.KeysAvailable, updates[3].Kind);
            Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[3].EncryptionLevel);
            Assert.True(schedule.HandshakeSecretsDerived);

            QuicTlsTranscriptProgress serverHelloProgress = new(QuicTlsRole.Client, selectedCipherSuite);
            serverHelloProgress.AppendCryptoBytes(0, updates[0].CryptoData.ToArray());
            QuicTlsTranscriptStep serverHelloStep = serverHelloProgress.Advance(QuicTlsRole.Client);

            Assert.Equal(QuicTlsTranscriptStepKind.Progressed, serverHelloStep.Kind);
            Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloStep.HandshakeMessageType);
            Assert.Equal(selectedCipherSuite, serverHelloStep.SelectedCipherSuite);
            Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, serverHelloStep.TranscriptHashAlgorithm);
            Assert.Equal(QuicTlsNamedGroup.Secp256r1, serverHelloStep.NamedGroup);
            Assert.False(serverHelloStep.KeyShare.IsEmpty);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleDriverAcceptsSupportedClientHelloConstructsServerHelloAndPublishesHandshakeKeys()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTlsCipherSuite[] selectedCipherSuites =
        [
            QuicTlsCipherSuite.TlsAes128GcmSha256,
            QuicTlsCipherSuite.TlsChacha20Poly1305Sha256,
        ];

        foreach (QuicTlsCipherSuite selectedCipherSuite in selectedCipherSuites)
        {
            QuicTlsTransportBridgeDriver driver = new(
                QuicTlsRole.Server,
                localHandshakePrivateKey: localHandshakePrivateKey,
                selectedCipherSuite: selectedCipherSuite);

            IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
            Assert.Single(bootstrapUpdates);
            Assert.Equal(QuicTlsUpdateKind.LocalTransportParametersReady, bootstrapUpdates[0].Kind);

            IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
                QuicTlsEncryptionLevel.Handshake,
                CreateClientHelloTranscript(
                    peerTransportParameters,
                    cipherSuites: [(ushort)selectedCipherSuite]));

            Assert.True(updates.Count >= 5);
            Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
            Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
            Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, updates[0].TranscriptPhase);
            Assert.Equal(selectedCipherSuite, updates[0].SelectedCipherSuite);
            Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, updates[0].TranscriptHashAlgorithm);
            Assert.NotNull(updates[0].TransportParameters);
            Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[1].Kind);
            Assert.Equal(QuicTlsEncryptionLevel.Initial, updates[1].EncryptionLevel);
            Assert.Equal(0UL, updates[1].CryptoDataOffset);
            Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, updates[2].Kind);
            Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, updates[3].Kind);
            Assert.Equal(QuicTlsUpdateKind.KeysAvailable, updates[4].Kind);

            byte[] surfacedServerHello = new byte[updates[1].CryptoData.Length];
            Assert.True(driver.TryPeekOutgoingCryptoData(
                QuicTlsEncryptionLevel.Initial,
                surfacedServerHello,
                out ulong offset,
                out int bytesWritten));
            Assert.Equal(0UL, offset);
            Assert.Equal(surfacedServerHello.Length, bytesWritten);
            Assert.True(surfacedServerHello.SequenceEqual(updates[1].CryptoData.Span));

            Assert.NotNull(driver.State.StagedPeerTransportParameters);
            Assert.Equal(peerTransportParameters.MaxIdleTimeout, driver.State.StagedPeerTransportParameters!.MaxIdleTimeout);
            Assert.Equal(peerTransportParameters.DisableActiveMigration, driver.State.StagedPeerTransportParameters.DisableActiveMigration);
            Assert.Equal(peerTransportParameters.InitialSourceConnectionId, driver.State.StagedPeerTransportParameters.InitialSourceConnectionId);
            Assert.Equal(selectedCipherSuite, driver.State.SelectedCipherSuite);
            Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, driver.State.TranscriptHashAlgorithm);
            Assert.True(driver.State.HandshakeKeysAvailable);
            Assert.True(driver.State.TryGetHandshakeOpenPacketProtectionMaterial(out _));
            Assert.True(driver.State.TryGetHandshakeProtectPacketProtectionMaterial(out _));
            Assert.False(driver.State.PeerFinishedVerified);
            Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
            Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
            Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleAcceptsClientHelloThatOffersApplicationProtocolNegotiation()
    {
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                peerTransportParameters,
                applicationProtocols: [SslApplicationProtocol.Http3.Protocol.ToArray()]));

        Assert.True(updates.Count >= 5);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.True(driver.State.HandshakeKeysAvailable);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleAcceptsCompatibilityClientHelloWithEmptySessionTicketAndPskModesOnly()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                extraExtensions:
                [
                    CreateClientHelloExtension(0x0023, []),
                    CreateClientPskKeyExchangeModesExtension(),
                ]));

        Assert.True(updates.Count >= 5);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.True(driver.State.HandshakeKeysAvailable);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleAcceptsClientHelloPskKeyExchangeModesListThatIncludesPskDheKe()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                extraExtensions:
                [
                    CreateClientPskKeyExchangeModesExtension(0x01, 0x00),
                ]));

        Assert.True(updates.Count >= 5);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleAcceptsClientHelloWithUnknownNonConflictingExtensionsAndTls13InSupportedVersionsList()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                supportedVersions: [0x7a7a, 0x0303, 0x0304],
                extraExtensions:
                [
                    CreateClientHelloExtension(0x0a0a, [0x01, 0x02, 0x03, 0x04]),
                ]));

        Assert.True(updates.Count >= 5);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakeKeysStayUnavailableUntilTheSupportedClientHelloCompletes()
    {
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: CreateScalar(0x22));

        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters);
        int partialLength = 12;

        IReadOnlyList<QuicTlsStateUpdate> partialUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHello[..partialLength]);

        Assert.Empty(partialUpdates);
        Assert.False(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            stackalloc byte[1],
            out _,
            out _));

        IReadOnlyList<QuicTlsStateUpdate> completionUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHello[partialLength..]);

        Assert.True(completionUpdates.Count >= 5);
        Assert.True(driver.State.HandshakeKeysAvailable);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnsupportedClientHelloTlsVersionFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                supportedVersions: [0x0303]));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnsupportedClientHelloCipherSuiteFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                cipherSuites: [(ushort)QuicTlsCipherSuite.TlsAes256GcmSha384]));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EmptyClientHelloApplicationProtocolNameFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                applicationProtocols: [Array.Empty<byte>()]));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NonEmptyClientHelloSessionTicketExtensionFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                extraExtensions: [CreateClientHelloExtension(0x0023, [0x01])]));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientHelloEarlyDataWithoutPreSharedKeyStillFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                extraExtensions:
                [
                    CreateClientPskKeyExchangeModesExtension(),
                    CreateClientHelloExtension(0x002a, []),
                ]));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientHelloPskKeyExchangeModesWithoutPskDheKeFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                extraExtensions:
                [
                    CreateClientPskKeyExchangeModesExtension(0x00),
                ]));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnsupportedClientHelloNamedGroupFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                supportedGroups: [0x11ec],
                keyShareNamedGroup: 0x11ec,
                keyShare: CreateSequentialBytes(0x90, 32)));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnsupportedClientHelloSupportedGroupsFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                supportedGroups: [0x001d]));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedClientHelloFramingFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateMalformedClientHelloTranscript(CreateClientTransportParameters()));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedServerRoleClientHelloProgressionIsRejectedDeterministically()
    {
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.True(firstUpdates.Count >= 5);
        Assert.True(driver.State.HandshakeKeysAvailable);

        IReadOnlyList<QuicTlsStateUpdate> repeatedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.Single(repeatedUpdates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, repeatedUpdates[0].Kind);
        Assert.Equal((ushort)0x0032, repeatedUpdates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedNeqoConnectionMigrationServerFirstFlightOpensWithPublishedSecrets()
    {
        byte[] originalInitialDestinationConnectionId = Convert.FromHexString("FA9C9302D36F956872087F0179AD05C356");
        byte[] protectedInitialPacket = GetCapturedNeqoConnectionMigrationServerInitialPacket();

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            originalInitialDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenInitialPacket(
            protectedInitialPacket,
            initialProtection,
            requireZeroTokenLength: true,
            out byte[] openedInitialPacket,
            out int initialPayloadOffset,
            out int initialPayloadLength));

        byte[] serverHello = ExtractFirstCryptoFrameData(
            openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength));
        AssertCapturedX25519ServerHello(serverHello);

        byte[] serverHandshakeTrafficSecret = Convert.FromHexString(
            "EDA8ABD662F4DB9E08F6037E4F6100DC99F5268F7428372F0C074EF3328DAD41");
        Assert.True(TryCreateHandshakePacketProtectionMaterial(
            serverHandshakeTrafficSecret,
            out QuicTlsPacketProtectionMaterial handshakeProtectionMaterial));

        byte[] protectedHandshakePacket = GetCapturedNeqoConnectionMigrationServerHandshakePacket();
        Assert.True(coordinator.TryOpenHandshakePacket(
            protectedHandshakePacket,
            handshakeProtectionMaterial,
            out byte[] openedHandshakePacket,
            out int handshakePayloadOffset,
            out int handshakePayloadLength));

        byte[] handshakeCrypto = ExtractFirstCryptoFrameData(
            openedHandshakePacket.AsSpan(handshakePayloadOffset, handshakePayloadLength));
        Assert.NotEmpty(handshakeCrypto);
    }

    internal static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    internal static QuicTransportParameters CreateClientTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
        };
    }

    internal static byte[] CreateClientHelloTranscript(
        QuicTransportParameters transportParameters,
        ushort[]? supportedVersions = null,
        ushort[]? cipherSuites = null,
        ushort[]? supportedGroups = null,
        byte[][]? applicationProtocols = null,
        ushort keyShareNamedGroup = (ushort)QuicTlsNamedGroup.Secp256r1,
        byte[]? keyShare = null,
        byte[][]? extraExtensions = null)
    {
        supportedVersions ??= [0x0304];
        cipherSuites ??= [(ushort)QuicTlsCipherSuite.TlsAes128GcmSha256];
        supportedGroups ??= [(ushort)QuicTlsNamedGroup.Secp256r1];
        extraExtensions ??= [];
        keyShare ??= CreateClientKeyShare();

        byte[] supportedVersionsExtension = CreateClientSupportedVersionsExtension(supportedVersions);
        byte[]? applicationProtocolsExtension = applicationProtocols is { Length: > 0 }
            ? CreateClientApplicationProtocolNegotiationExtension(applicationProtocols)
            : null;
        byte[] supportedGroupsExtension = CreateClientSupportedGroupsExtension(supportedGroups);
        byte[] keyShareExtension = CreateClientKeyShareExtension(keyShareNamedGroup, keyShare);
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Client);

        int extensionsLength = supportedVersionsExtension.Length
            + (applicationProtocolsExtension?.Length ?? 0)
            + supportedGroupsExtension.Length
            + keyShareExtension.Length
            + SumLengths(extraExtensions)
            + transportParametersExtension.Length;
        byte[] body = new byte[43 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;
        CreateSequentialBytes(0x10, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;
        body[index++] = 0;

        WriteUInt16(body.AsSpan(index, 2), checked((ushort)(cipherSuites.Length * 2)));
        index += 2;
        foreach (ushort cipherSuite in cipherSuites)
        {
            WriteUInt16(body.AsSpan(index, 2), cipherSuite);
            index += 2;
        }

        body[index++] = 1;
        body[index++] = 0x00;
        WriteUInt16(body.AsSpan(index, 2), checked((ushort)extensionsLength));
        index += 2;

        supportedVersionsExtension.CopyTo(body.AsSpan(index));
        index += supportedVersionsExtension.Length;
        applicationProtocolsExtension?.CopyTo(body.AsSpan(index));
        index += applicationProtocolsExtension?.Length ?? 0;
        supportedGroupsExtension.CopyTo(body.AsSpan(index));
        index += supportedGroupsExtension.Length;
        keyShareExtension.CopyTo(body.AsSpan(index));
        index += keyShareExtension.Length;
        foreach (byte[] extraExtension in extraExtensions)
        {
            extraExtension.CopyTo(body.AsSpan(index));
            index += extraExtension.Length;
        }

        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    internal static byte[] CreateMalformedClientHelloTranscript(QuicTransportParameters transportParameters)
    {
        byte[] transcript = CreateClientHelloTranscript(transportParameters);
        ushort declaredExtensionsLength = (ushort)(BinaryPrimitives.ReadUInt16BigEndian(transcript.AsSpan(43, 2)) + 1);
        BinaryPrimitives.WriteUInt16BigEndian(transcript.AsSpan(43, 2), declaredExtensionsLength);
        return transcript;
    }

    private static byte[] CreateClientSupportedVersionsExtension(IReadOnlyList<ushort> supportedVersions)
    {
        byte[] extension = new byte[2 + 2 + 1 + (supportedVersions.Count * 2)];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x002b);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(1 + (supportedVersions.Count * 2))));
        index += 2;
        extension[index++] = checked((byte)(supportedVersions.Count * 2));
        foreach (ushort supportedVersion in supportedVersions)
        {
            WriteUInt16(extension.AsSpan(index, 2), supportedVersion);
            index += 2;
        }

        return extension;
    }

    private static byte[] CreateClientApplicationProtocolNegotiationExtension(IReadOnlyList<byte[]> applicationProtocols)
    {
        int protocolListLength = 0;
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            protocolListLength += 1 + applicationProtocol.Length;
        }

        byte[] extension = new byte[2 + 2 + 2 + protocolListLength];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0010);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + protocolListLength)));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)protocolListLength));
        index += 2;
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            extension[index++] = checked((byte)applicationProtocol.Length);
            applicationProtocol.CopyTo(extension.AsSpan(index));
            index += applicationProtocol.Length;
        }

        return extension;
    }

    private static byte[] CreateClientSupportedGroupsExtension(IReadOnlyList<ushort> supportedGroups)
    {
        byte[] extension = new byte[2 + 2 + 2 + (supportedGroups.Count * 2)];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x000a);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + (supportedGroups.Count * 2))));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(supportedGroups.Count * 2)));
        index += 2;
        foreach (ushort supportedGroup in supportedGroups)
        {
            WriteUInt16(extension.AsSpan(index, 2), supportedGroup);
            index += 2;
        }

        return extension;
    }

    private static byte[] CreateClientKeyShareExtension(ushort namedGroup, byte[] keyShare)
    {
        byte[] extension = new byte[2 + 2 + 2 + 2 + 2 + keyShare.Length];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + 2 + 2 + keyShare.Length)));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + 2 + keyShare.Length)));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), namedGroup);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)keyShare.Length));
        index += 2;
        keyShare.CopyTo(extension.AsSpan(index, keyShare.Length));
        return extension;
    }

    private static byte[] CreateClientPskKeyExchangeModesExtension(params byte[] modes)
    {
        if (modes.Length == 0)
        {
            modes = [0x01];
        }

        byte[] extensionValue = new byte[1 + modes.Length];
        extensionValue[0] = checked((byte)modes.Length);
        modes.CopyTo(extensionValue.AsSpan(1));
        return CreateClientHelloExtension(0x002d, extensionValue);
    }

    private static byte[] CreateClientHelloExtension(ushort extensionType, ReadOnlySpan<byte> extensionValue)
    {
        byte[] extension = new byte[4 + extensionValue.Length];
        WriteUInt16(extension.AsSpan(0, 2), extensionType);
        WriteUInt16(extension.AsSpan(2, 2), checked((ushort)extensionValue.Length));
        extensionValue.CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static int SumLengths(IReadOnlyList<byte[]> arrays)
    {
        int sum = 0;
        foreach (byte[] array in arrays)
        {
            sum = checked(sum + array.Length);
        }

        return sum;
    }

    private static byte[] CreateClientKeyShare()
    {
        using ECDiffieHellman clientKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        clientKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(0x11),
        });

        ECParameters parameters = clientKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[65];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] CreateTransportParametersExtension(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole role)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            role,
            encodedTransportParameters,
            out int bytesWritten));

        byte[] extension = new byte[4 + bytesWritten];
        WriteUInt16(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)bytesWritten);
        encodedTransportParameters.AsSpan(0, bytesWritten).CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), body.Length);
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    internal static byte[] CreateCapturedQuicGoServerHandshakeClientHelloTranscript()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            Convert.FromHexString("E06C84EB090F316A4C270E"),
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new();
        SortedDictionary<ulong, byte[]> segments = [];
        foreach (string packetHex in
            new[]
            {
                "C3000000010BE06C84EB090F316A4C270E000044EB7283E787021036CA43E3B9E3ACC8786C6A86E058145F118A8D97CB19B7A757FB95AF281A2E8AACE7FCCAA423ACF9608825A4E673A9D2D8388F74E78C4625900097F3A9B6A645E82D6D16542D1A36B95283E2059FDDDFE5FEDD5AF549BED2BDC8FD9544FAE65C5259D32D1A20FCBBF0CE36C5A470D638CF16652B355AC4BDD4BC271EADA0AD61ACB8CFF66207949CD7884C92CC2A101C47CFE4E37C8FA313F1723A49EFAABC9009AFC4975A75DD2B304473144D71B08EF55E1D639D6993A7CAFE665FFA29458580292383B4FA27195514AB0B92510A05D3C70671BB1D59245A78D21F5607DFE1F71EB79E5390BF84B5AEA6636B722371D9F3587A1B2AAB32C94E6F2AB4AD7323132F48CC75D7BCB833D62EDEC6E2A352311CF2B7C078ACE9E41185B56BCF30BD16252F79170042D4E83A9E6100DF1336C00B7BCE46EBC5239BFCE2C0159C6CE6FFB437186059259A18A028D227034CAE5E6671652D70D51450970E3E82B82DBA7960B0F51DB3E12AC5AF28AFDE2384DCF9F6D88B4A7720D2672BD940A30F76E059D23F8C0E281C58D51E3EEC523DC2D520F0D61DC45CD2B7FAE859BC29A019B24665FAE4B0B74E728B2BD01CE350664B0619631457814BB2B9E055E20248E076B0D7226622AF2C2D9FF5C7D3BA2C5139A048B7D8968B7EA8896D563829171DC2F17303D905EC1F33C31105ADC84003F4DCAEF7637CDDE7286F6AF80FF6829A5CCD5F1C150BB00844250F2DADABD90CEF561EC2E6222B3FB88B68968F78B268FE6EAAAA1E0F6120E0EB254509E8078CE89D99A841640C53EE38357BA4AB011B75C8EAA32584DF276EB47DF20C6A5584B6004A8A338C2DDC68C28788EB0CA010733DC03B42B71582E36B0EE973DF3D919F0C46B8BB48CDA2171A03798952ACB620D8B48640CF98814764B968DB6A04314D38AA67AD068BA665F34B4082AC1913C9CBFB2F2A3D487260F8FA82FB9A0B963ACACF2FEFDD37F53F4B4CE09B749B222550C28FF0C0A37315C3C8E8869878C00B04D8D16083B9D8D5DE5E05B1BA2BDCBD59EB04399E002C7D216C27272171ED5EBF0C052D865F3398CFF5523084916832900BF658C4299C5649D120F67D85D547D3037EFEFBF39F09EA8EDDF2608A1EFEC6394DAA762C865D8D55B0FC6EFF42F8F337B68CC926BC31F289D19CB9E62AF3C45C25858FF14791F55E18926A03197E64306D7EE6BE21EAA817943A7A7AE0F844690F8C623AFC54F7C7172D9935AB3F05597A769C44C5E466A910A4C2125E9718F80FD54105B625309189211E53CE720E54403B3E206846E4DBD66067DF99A11BD5DB2B04768C0029C2BC679351BB22FA66B38DE5B2C80A874009AC03DA25817586F6D2D192F64AE63AA9CCCEE1FC3C21B7A1AEA2E9C90ACECCDCFF19C7D3E365176FB1A2092A56088913CD4DD23D04AA13FE7BF0A9D09FD563E5BDA3910A603F279BEBC3072F25ED15B8B7D7751A081A95049668476E0FAA32E933F2D6D5F5DE05E02B632D2079971896A0364E5E483BD45D11AEEAEDCAC9391EB52E86A042C611B8503ED9F10AEFC80E95D3704825D5C164B1D784D3AAA50092691E54F78DC54332E616BA305BDF5853B73A7DA943A6010C8DB28232DC57BEB84D6C48AFEEB3BFBFEBD1B79BAA5914D2B6D3A4C35A4B97C2A1C987A63D7B2EAE0ED60BBD855A96483613137FAB53123E2A6F45CE40DF11E7E98E535316B974484D28AF27B740B5CB5DF0A70312068776566D567E4690C6B4C8F1DD859874DA0D010196906A866D846C63",
                "C6000000010BE06C84EB090F316A4C270E000044EBF645C5CAD03C98CDDA96258E9C84969588E7C2EAF097EF0C9EB7B7CEE17C8A30C6FD8DAFBE812BDEBBEE9D2B6DB8313BBFAD8BC4FC2344BB3A77BFA0C4D140A8C03C3E55982C0642FE50D9EA9E46DE1AFD2AD16E04AEA2E7CC2E853A2C1017E6F2F5D61C5277EEAF3BD784549C59FAE2C3DE60E71EFFC32838F7D2F38569E4C557EAAFF09BACC1B5FD5F44B23629445E54E7EE5E014F2439324B44D1F4FCE174D401BFE0F3FFB449CD22818FA8E299E362F56856DF62EDCAB64F32D9076E282302426FF5B2BDD7DFB46BE690B1DE6655E40694D7982C0F2E37525BA4EA745E1CA700BC22B8DF8AAA818B6BB01AEDD2FAA0E400C045F4C241B6FF10662BB4EBA0DEFC9ABA149D5155106E382B309638711A76CD05170BFC2BA6115F30A8074EA029A8227AD59723A84ED4171B67A90D328AAF279CCC4BECABAF070750A51E76E3415DE4678F78D7993B4B02D253C60400AC0F3C9092D8C148A7495D0888E4615FC71FFB8201636CC8192CFB24D439950344710925AB5D3316057AC7A3AD85348CB14CCB564EDBD0CE6A33D32B23D04DECE8EA9D87ABC50C25A4D39F004957DBF16EF1E73DEF716D73469DAE06C0F742C383926514FEAC87675C849CB7ADAB18AED688920F7A12F8193BFC040C9D4FA9BEEBDF456EEFCFA9F97C27C5B969A15DBBE1BF99A1614215A6CA7DF3DCD7CE237398D91AB233CD7B960CCD0AD50DD5FEF1A7075DED329D7B69ABE7C46CADCDD447F631A04D81421871E7832DA9B4EEDC979920F8A56C1D5C5C898199D739993DA3D0AC592AC9ED62E0A619550ECE65D6238141A161EB055228C7EC392E2811A345DF04CB93865C1108605534E9E34398D30287522C10EB4E539D2CA68B89835A1540A12182D23318AC4B6C97523F878465521340303EC15DB198C269D676C689FA81D99D6A748E447235C6A2957D086220452DE940794FFAA57877ED66F4FF4636D0B3782D7820E99A69A2BA6F6CB02C69B7FE0D79C1CB0EDC2B3F78C98EBC15AF5A66CA12758BB40AD7189A21669B292C53BB496547350713E0A53DA5B575254BBA764839F833849CD371BC8F375FBB8EB714E4369E7A5203FCBF42D5915688784F6F27557FB0E5CD8DDD561C25A5709B61AA4621CA92F934BB65112051E9A9CEF4ED978C7E6D0DB7A37C520CEBE2AEED9CD7DB9F0E80DC7135A4640EBD41884BD143A38D66D51AE0FD3388CF59F0CB8FBD61130838FC7F224EDB46EBD983E4F94B87C67814A4AB4784FB1903280DC6D15D9415EC824FEBCAF1ED6B47A97FDD6192E608057CC12C7EF6BC115A2DD55F01C56E042DCEC96453333B1CCA594131A6505F055E9E43D3E88418ADE8C91E8C2493669F59147DCC9846E7B0DDE9CB5BE02824E04B9BBFA724F8F9A0D56200C8621EF3E955106A3A2DDE9BAEC296BC7B0488393B8CF298BD9C08D9FF892A13282FC2FF929AF9193B81B07F765CF172A057D157EC3AAA5BE5B1C25C3101468FCEB4C41CBCE30588FB44056365E75EFF7F5C3D8F2EFDF03C18386D9265295C99DC92CECEE76BFE1FCD1356DEB54950DBF1111F49D9E75DEE375F46F3DB63461747270B81407FC5660E684CD313D0EE5CB2E3973E41E77664A7B3C5026360AD157B4F80725191B4C1897603E4E9E133F370573A3BC17BD0EB8399391AC6915C9FE7F4E279036EA48D74336EDFF3B64CDE0E01A1A14E0CCF4CAAE74EFC1BF8E361887323EEFCC18C2D3B8352D705832A5C478D9F8ED191C436AF47FC7F83D6AD5DBA63FEAAC66A88AA9F61A4C010",
            })
        {
            byte[] packet = Convert.FromHexString(packetHex);
            Assert.True(coordinator.TryOpenInitialPacket(
                packet,
                protection,
                requireZeroTokenLength: false,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            CollectCryptoSegments(openedPacket.AsSpan(payloadOffset, payloadLength), segments);
        }

        int totalLength = 0;
        foreach ((ulong offset, byte[] data) in segments)
        {
            totalLength = Math.Max(totalLength, checked((int)(offset + (ulong)data.Length)));
        }

        byte[] transcript = new byte[totalLength];
        foreach ((ulong offset, byte[] data) in segments)
        {
            data.CopyTo(transcript.AsSpan(checked((int)offset)));
        }

        return transcript;
    }

    internal static byte[] CreateCapturedNeqoConnectionMigrationClientHelloTranscript()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            Convert.FromHexString("59B87C5DA7DD98C792AC"),
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new();
        SortedDictionary<ulong, byte[]> segments = [];
        foreach (string packetHex in
            new[]
            {
                "C4000000010A59B87C5DA7DD98C792AC000044BCB91FE876A57AA1BD062DC821A2597C11DC54B4E550ADD7373BF1CF62791143F4BD2954A4F292F96CBC3B663E646587BBDA3E4C16DFC17E42A827E068AA016E130911D037EAA03A2EA3EED119BC532DD884672DCB12F9D48C5277F0417DE48785000DF1F21D4167A605E4DB184B2BC4CE80B0BDB83A51130B71AB5DF6F0FF86214B4E464FB3FAB862B0CD849B12A7CE15E8DBBCE4ED5F898A755946C43DAA5C3CA93C831C70D61B32B2E848401A534BF93ED134C1B3B071DA51D530AE8A7AC4A77345EBAD5B024B30ECABD3EE4EC024E56EDFF2A450C44577E6532C9D1F8AEAE9BCCB8A75F8FDA3DB12E9868ADCD9544BC0942B01CB228ADDA4BBE8501FDF7C0E5F37D01E594F6A0A12678023B16A371A4042DE3AF096410F27675D5B85D3B3D92F211D097559D0A601EAAF684C3E2BAD08EC04B598AFEEDE0F4E9A49B38F20A360C746DCCB23E276BA2336FAF499EC85672425DBB9A437010948BA53FE71ABFAADC1D087A121816993D3432229CCA1A1A6CF502241D7EBBFB844DF4E0420BAF7ECD4A3E910FE5CE747C973F64CB5682DF91267E997D51E1DC892C102248C62FFB5C3F17C7C94AA80EE33826881378BE6ABA51A050B97D2A83A38E3370E093522BA068116146A8763D21EA60B26C6B6E6FB04FB7749E0512EB9BE2F84A60583685132778B4F7E2D6C8F809DA4651F4AF25726F76EB2D49955AAD664139EBE2E423DD54F93DE5783117E9CAE0A7BEB80170377107135B65D846AAC2EEACFA0DB54636073FD85B667D431ECF219D7682B162EA49E835406B5E46FF42F533D0F85ACC5D7F26B74C3D7CCCFA9ABCBC8DFB89F80FC18D61D48168F7F69EF113CAD3EAE84048090DD9B3CCA8B84671F9AFAEAC7F4E6191548DD9334D37FE63DB093B1C20477981E2D5A7922E0B6E5857FE8020137541D5244CA64C4FFCB1F9EBF9BBD05A203911CB0881695334256BFBFFA1C1011B1C983963B24F6229C2BCB22372AB96008111A2305BD49D5BE88DAFF9BC50F8875535E1EB62D3E3A6342D8149B66EF82FD6970213344755ABA0F8117C24CBF91A34639BD2B13B86637D949B050FA2D54322707AA0EEA10216584D2AD39EDC6D98DA732E9EC74443BCA426C0772164C00275439797C060ED6C744C40CD994D834938F80E37E7CFDB30525F7F1CB4E6DBC0D8847ECCFD90B55A2E442A398C25DF4AAF759DA38C6D25F57D1D4AA3B654C5C58FBA2C2DB4823D1779B257E2E0394BDD769C78E61DBC12040416FD74518CC7454EC940B4079BBE7C9655065DF28F5E52BE8CD39FF1C5B7C6DD0C1A6A56AFAC825DE9BA9413D6420E9B372F6FA03DA480769A680B1A492E587F00DA35AC8AE160F0DB19A1743B793827DCE000A476321A85FDA07DC27C0794F595E422CA61D0DFCB485DD6F9AF2B8D707CFB4E36F58B8F1EB1CD7AF8617C7B74EF0CDC18C216BE36A784A6D091B6F26685E642B611C3481DBF8DB97106B008CF90DC5EE271D55C570A64A9B37596A9DBBCB275167C0A9CD80E8177B8D609A1307205DBE87E70BFA8D98319A54A0E3777CD743AA83CB3FD69C71C913D572050021C8891117E5173195BD75337700275141589680C105A8B9AF9B28F4080B1B142CDD260C2AD1D8ECDEDF131E00354087560E830048BA3E83CB66603FDB819B5CD45B34AC118962E389390FFC4C18EDCAC1474427D071EF44D6FD3DF6521DDF83D438",
                "CE000000010A59B87C5DA7DD98C792AC00004172E16CFE7409417CCD421D9F0B64F4719871845F73BCFF1BAA483C922F15E95EC3F8872C77AC7B042D79E9A2006409C867917A375F97F21D7A264D10B6A8D61AE90E74333D15C1AAB9EC60F67CB700A90FE1EBEF2E6639ED3F97C2C69155B7CD2979C2DC725BFE7240A524C5D2FCA31687F0A179CDC1B8740CBDCA2B7B01C4905136E688B68899297548EA5E57D3E27682C1F4F8FA965FB21DA240232AB933A6CD71506A1BB200709F09A09E20A93D376EFE64B0D71331A38B9781DFB97F2FC99B753158E74EF3AC51B290EA44513048893A4BEBAB4A1316AB5CDF2BE6851882876A18D9B723E013020BF7C1C2E2BDCE8EBDE9D137AB509E300CD67DC6D951CD7226D6C503BA8A75CFB16C7C41A12F7BF41CE59EEA1F502C794D65DC422045D2251FD8077D5F9CB4C5B0767779E7F1233C30EABE79E84C2104D7F37CB290CAE3A45ED3350A7BB6B52BFB5E291B56BDA517096EFBB069831FD2F75218ED758620A80FED704449CC1AEB6A4653B698C249362663",
            })
        {
            byte[] packet = Convert.FromHexString(packetHex);
            Assert.True(coordinator.TryOpenInitialPacket(
                packet,
                protection,
                requireZeroTokenLength: false,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            CollectCryptoSegments(openedPacket.AsSpan(payloadOffset, payloadLength), segments);
        }

        int totalLength = 0;
        foreach ((ulong offset, byte[] data) in segments)
        {
            totalLength = Math.Max(totalLength, checked((int)(offset + (ulong)data.Length)));
        }

        byte[] transcript = new byte[totalLength];
        foreach ((ulong offset, byte[] data) in segments)
        {
            data.CopyTo(transcript.AsSpan(checked((int)offset)));
        }

        return transcript;
    }

    private static void CollectCryptoSegments(
        ReadOnlySpan<byte> payload,
        SortedDictionary<ulong, byte[]> segments)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int cryptoBytesConsumed))
            {
                Assert.Fail($"The captured Initial payload contained an unexpected frame at offset {offset}: 0x{remaining[0]:X2}.");
            }

            segments[cryptoFrame.Offset] = cryptoFrame.CryptoData.ToArray();
            offset += cryptoBytesConsumed;
        }
    }

    internal static string DescribeClientHello(byte[] clientHello)
    {
        int index = 4;
        ushort legacyVersion = ReadUInt16(clientHello, ref index);
        index += 32;
        int sessionIdLength = clientHello[index++];
        index += sessionIdLength;

        ushort cipherSuitesLength = ReadUInt16(clientHello, ref index);
        List<string> cipherSuites = [];
        int cipherSuitesEnd = index + cipherSuitesLength;
        while (index < cipherSuitesEnd)
        {
            cipherSuites.Add($"0x{ReadUInt16(clientHello, ref index):X4}");
        }

        int compressionMethodsLength = clientHello[index++];
        index += compressionMethodsLength;

        ushort extensionsLength = ReadUInt16(clientHello, ref index);
        int extensionsEnd = index + extensionsLength;
        List<string> extensions = [];
        while (index < extensionsEnd)
        {
            ushort extensionType = ReadUInt16(clientHello, ref index);
            ushort extensionLength = ReadUInt16(clientHello, ref index);
            extensions.Add(DescribeClientHelloExtension(extensionType, clientHello.AsSpan(index, extensionLength)));
            index += extensionLength;
        }

        return $"legacy=0x{legacyVersion:X4}; cipherSuites=[{string.Join(", ", cipherSuites)}]; extensions=[{string.Join(", ", extensions)}]";
    }

    private static string DescribeClientHelloExtension(ushort extensionType, ReadOnlySpan<byte> extensionValue)
    {
        if (extensionType == 0x000A)
        {
            int index = 0;
            ushort groupsLength = ReadUInt16(extensionValue, ref index);
            List<string> groups = [];
            int groupsEnd = index + groupsLength;
            while (index < groupsEnd)
            {
                groups.Add($"0x{ReadUInt16(extensionValue, ref index):X4}");
            }

            return $"0x{extensionType:X4}(groups={string.Join("/", groups)})";
        }

        if (extensionType == 0x000D || extensionType == 0x0032)
        {
            int index = 0;
            ushort schemesLength = ReadUInt16(extensionValue, ref index);
            List<string> schemes = [];
            int schemesEnd = index + schemesLength;
            while (index < schemesEnd)
            {
                schemes.Add($"0x{ReadUInt16(extensionValue, ref index):X4}");
            }

            return $"0x{extensionType:X4}(schemes={string.Join("/", schemes)})";
        }

        if (extensionType == 0x002B)
        {
            int index = 0;
            int versionsLength = extensionValue[index++];
            List<string> versions = [];
            int versionsEnd = index + versionsLength;
            while (index < versionsEnd)
            {
                versions.Add($"0x{ReadUInt16(extensionValue, ref index):X4}");
            }

            return $"0x{extensionType:X4}(versions={string.Join("/", versions)})";
        }

        if (extensionType == 0x0010)
        {
            int index = 0;
            ushort protocolsLength = ReadUInt16(extensionValue, ref index);
            List<string> protocols = [];
            int protocolsEnd = index + protocolsLength;
            while (index < protocolsEnd)
            {
                int protocolLength = extensionValue[index++];
                string protocol = System.Text.Encoding.ASCII.GetString(extensionValue.Slice(index, protocolLength));
                protocols.Add(protocol);
                index += protocolLength;
            }

            return $"0x{extensionType:X4}(alpn={string.Join("/", protocols)})";
        }

        if (extensionType == 0x0033)
        {
            int index = 0;
            ushort keyShareLength = ReadUInt16(extensionValue, ref index);
            List<string> keyShares = [];
            int keyShareEnd = index + keyShareLength;
            while (index < keyShareEnd)
            {
                ushort namedGroup = ReadUInt16(extensionValue, ref index);
                ushort keyExchangeLength = ReadUInt16(extensionValue, ref index);
                keyShares.Add($"0x{namedGroup:X4}:{keyExchangeLength}");
                index += keyExchangeLength;
            }

            return $"0x{extensionType:X4}(keyshare={string.Join("/", keyShares)})";
        }

        if (extensionType == QuicTransportParametersCodec.QuicTransportParametersExtensionType)
        {
            List<string> parameters = [];
            ReadOnlySpan<byte> remaining = extensionValue;
            while (!remaining.IsEmpty)
            {
                if (!QuicVariableLengthInteger.TryParse(remaining, out ulong parameterId, out int idBytes))
                {
                    parameters.Add("<bad-id>");
                    break;
                }

                remaining = remaining[idBytes..];
                if (!QuicVariableLengthInteger.TryParse(remaining, out ulong parameterLength, out int lengthBytes))
                {
                    parameters.Add($"0x{parameterId:X}:<bad-length>");
                    break;
                }

                remaining = remaining[lengthBytes..];
                parameters.Add($"0x{parameterId:X}:{parameterLength}");
                if (parameterLength > (ulong)remaining.Length)
                {
                    parameters.Add("<truncated-value>");
                    break;
                }

                remaining = remaining[(int)parameterLength..];
            }

            return $"0x{extensionType:X4}(tp={string.Join("/", parameters)})";
        }

        return $"0x{extensionType:X4}(len={extensionValue.Length})";
    }

    private static byte[] ExtractFirstCryptoFrameData(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out _))
            {
                return cryptoFrame.CryptoData.ToArray();
            }

            Assert.Fail($"The captured payload contained an unexpected frame at offset {offset}: 0x{remaining[0]:X2}.");
        }

        Assert.Fail("The captured payload did not contain a CRYPTO frame.");
        return [];
    }

    private static void AssertCapturedX25519ServerHello(ReadOnlySpan<byte> serverHello)
    {
        Assert.True(serverHello.Length >= 4);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.ServerHello, serverHello[0]);

        int index = 1;
        uint bodyLength = ReadUInt24(serverHello, ref index);
        Assert.Equal(serverHello.Length - 4, checked((int)bodyLength));
        Assert.Equal(0x0303, ReadUInt16(serverHello, ref index));

        index += 32;
        int sessionIdLength = serverHello[index++];
        index += sessionIdLength;

        Assert.Equal((ushort)QuicTlsCipherSuite.TlsAes128GcmSha256, ReadUInt16(serverHello, ref index));
        Assert.Equal(0x00, serverHello[index++]);

        int extensionsLength = ReadUInt16(serverHello, ref index);
        int extensionsEnd = index + extensionsLength;
        bool foundSupportedVersion = false;
        bool foundKeyShare = false;
        while (index < extensionsEnd)
        {
            ushort extensionType = ReadUInt16(serverHello, ref index);
            int extensionLength = ReadUInt16(serverHello, ref index);
            ReadOnlySpan<byte> extensionValue = serverHello.Slice(index, extensionLength);
            index += extensionLength;

            if (extensionType == 0x002B)
            {
                int extensionIndex = 0;
                Assert.Equal(0x0304, ReadUInt16(extensionValue, ref extensionIndex));
                Assert.Equal(extensionValue.Length, extensionIndex);
                foundSupportedVersion = true;
                continue;
            }

            if (extensionType == 0x0033)
            {
                int extensionIndex = 0;
                Assert.Equal((ushort)QuicTlsNamedGroup.X25519, ReadUInt16(extensionValue, ref extensionIndex));
                int keyShareLength = ReadUInt16(extensionValue, ref extensionIndex);
                Assert.Equal(QuicTlsX25519.KeyLength, keyShareLength);
                Assert.Equal(extensionValue.Length, extensionIndex + keyShareLength);
                foundKeyShare = true;
                continue;
            }

            Assert.Fail($"Unexpected captured ServerHello extension 0x{extensionType:X4}.");
        }

        Assert.Equal(extensionsEnd, index);
        Assert.True(foundSupportedVersion);
        Assert.True(foundKeyShare);
    }

    private static bool TryCreateHandshakePacketProtectionMaterial(
        ReadOnlySpan<byte> trafficSecret,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        byte[] aeadKey = HkdfExpandLabel(trafficSecret, QuicKeyLabel, [], 16);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, QuicIvLabel, [], 12);
        byte[] headerProtectionKey = HkdfExpandLabel(trafficSecret, QuicHpLabel, [], 16);
        if (!QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits usageLimits))
        {
            return false;
        }

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            usageLimits,
            out material);
    }

    private static byte[] HkdfExpandLabel(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        int length)
    {
        const int HkdfLengthFieldLength = sizeof(ushort);
        const int HkdfLabelLengthFieldLength = 1;
        const int HkdfContextLengthFieldLength = 1;
        const int HkdfExpandCounterLength = 1;
        const byte HkdfExpandCounterValue = 1;
        byte[] hkdfLabelPrefix = System.Text.Encoding.ASCII.GetBytes("tls13 ");
        int hkdfLabelLength = HkdfLengthFieldLength
            + HkdfLabelLengthFieldLength
            + hkdfLabelPrefix.Length
            + label.Length
            + HkdfContextLengthFieldLength
            + context.Length;

        byte[] hkdfLabel = new byte[hkdfLabelLength];
        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel.AsSpan(0, HkdfLengthFieldLength), checked((ushort)length));
        hkdfLabel[HkdfLengthFieldLength] = checked((byte)(hkdfLabelPrefix.Length + label.Length));

        int index = HkdfLengthFieldLength + HkdfLabelLengthFieldLength;
        hkdfLabelPrefix.CopyTo(hkdfLabel.AsSpan(index));
        index += hkdfLabelPrefix.Length;

        label.CopyTo(hkdfLabel.AsSpan(index));
        index += label.Length;

        hkdfLabel[index++] = checked((byte)context.Length);
        if (!context.IsEmpty)
        {
            context.CopyTo(hkdfLabel.AsSpan(index));
        }

        byte[] expandInput = new byte[hkdfLabel.Length + HkdfExpandCounterLength];
        hkdfLabel.CopyTo(expandInput);
        expandInput[^1] = HkdfExpandCounterValue;

        using HMACSHA256 hmac = new(secret.ToArray());
        byte[] output = hmac.ComputeHash(expandInput);
        if (output.Length == length)
        {
            return output;
        }

        byte[] truncated = new byte[length];
        output.AsSpan(..length).CopyTo(truncated);
        return truncated;
    }

    private static byte[] GetCapturedNeqoConnectionMigrationServerInitialPacket()
    {
        return Convert.FromHexString(
            // Captured from hosted run 25868496912:
            // runner-logs/nginx_neqo/connectionmigration/server/qlog/server-connectionmigration-578bcedf4a0543cc9bcd300bd49ba79f.qlog
            "CD000000010008CF5BA02E6C46FAB900449E63F248BD090C6F235437F121861B5511D3A34635B2B773705AB7373722BA" +
            "9927995C53EEB6093A77DBDCC14AE55191C897D8B9C91D41D154E29926BBDCA90A61E9A45E5A4DAC246021C089545B5D" +
            "2F10CEBA29F8FAFABB980FAF92BE7352AB01816BAFE5C9369F7A8518A49E7E3C5F069F48D8912B3E82AF113F2BD13C4C" +
            "B7E12F3D7B75903D2BDFB56A6F4755F5E08CC685DB99EF5A50BC4C62F835CBBB368F25169636B85A0A80ED04135BBD4A" +
            "D7321407E51913086CB9A404897FDF814821B7E3B6466293880A0BAA9362BD628D75342DD2E2C922F003652C887C17D7" +
            "9DE4FB7BD2627E72BE1614147F8BD60B11E9620BAEC85FDB368369393842A8EE4029EEC192A57432A44AF4CE29589FEF" +
            "476AF27ED971E7E723CF161C420698AE59BB902A33CCE37D8AF85C3480303EE3CF4B1088EB8E49395A6BC987A9BADC50" +
            "6D4E7249A0268A9CD4E4995B19FD432711D1F907131E52C70B246AFB65602575FC86849FCB205578FA0CE12C2919F670" +
            "D34B78147D413A3695FF9D012CC79128946DF1C2D68DAD58E16AD7792AC9967355CBDF5B53AB3619253EDA008F36553C" +
            "3F8E034C46471BFDB240AA450B865F1C19DE949AF645479C12DD068C70FEAE174DC63D07220B9A2D2CEE857BD91303B4" +
            "B4AFE4B08E3B0A9623B0C82B906D74EB9F6A6507DA043A90374AE96EE7CA7D65CB7A19180CA745DA26D4F9903C31E317" +
            "CDD5CEC53F6557BD4D90A5F49E1408099C16EC204A14D4BE0EC65C36F7EDEFEE42C40115BF2B7FB58875668A1EDF7B8F" +
            "723965E8B8D393F190E02C8FC39519C959FDFDADD9CBC7B2AD6B691942889FFC4556EF32E7718BC606C2CFE1B22A9320" +
            "A9F51E73A1B0C10BC96143E6135B386E89BD1133E04A407350EAC6B019DD5A742812B21499CDD84A644527E83C8215C7" +
            "988937F11E5A1B5B5E4662B69B1E709D3F76B0B887B722A128448D06C359A3F51FD46339C2B859A785FB0A0BCEABA7D0" +
            "ACD6B16329B232C3AB54A2D8F099873EBF43EDF50E3390B3FC7FC0A23F982EA97392E55DD43FB0A8EE6BD3EA5232E181" +
            "8CE6611D9384219C3B4D6014D81C36A635214478FA4823BC770FCF3DBBBF13CA8C19FD610BA8758F755647C0ACE5BE17" +
            "02374D22224BA3F27E1CD82843769DE11C2BEF3275955F3A4EF28A9F06041E502629AF39F83F51C31CBE5A67F63A3C33" +
            "E36927718D7D3E7501686D0C3A9C2D09FA58AF103BFE92FA5C823FAEC6440BAF45B7A015785AC68AFFBEFFBC6E7C660A" +
            "A8F13D6074B03F2214FAA39A4A468B9ABA9CB808B4EE616D8FC1FBC9A33E509EF4A5BEE3BB09C57A95CE4950A4F90B99" +
            "9BCB1E924949EB799C9C5218B2264DA798A6B9679C68E4B2891D80DC08D413FC7790DCEA1C0CB4F5F38E94EED3A9AF7A" +
            "68C1584A29C78F5915C86CEB7C07E431EB1AB4CD6E0FD021BB4E5C56A83F9DB0512A352558F3E5410A4CECD453A613D4" +
            "BA7AB4D6D6539238109976E3C40E0466EE81AD13D4D7982432D96A200B1742776CCA48A258E388A4ECE4912559F783B2" +
            "6711B8F0B713FB2E0631C41B47A4F3915A9F6C5CA2F405830C7419756C2C90C61437B655BD6D6958F34B3D757293F698" +
            "5F33D1ED243FD25BC54BE3A8B10D9A4DD9C89211ED90485E9F59470993531855D6B479FD10BF55251280AAF59D90EC0E");
    }

    private static byte[] GetCapturedNeqoConnectionMigrationServerHandshakePacket()
    {
        return Convert.FromHexString(
            // Captured from the same hosted run 25868496912 qlog as the server Initial packet above.
            "E3000000010008CF5BA02E6C46FAB942F0F0F52C16D99D8B01BA70E682403A9B8482381786808A22F52C4033C7D0AA96" +
            "AC85361E6030B02AF0800B07D419CCC32327CCDDEBC552BE57C0953A22CA872124F0982D8C6BE4C55783C64B94B46656" +
            "5C221285F1E0E7083454C6C08FD7D0A44968440EBA497D4A3A3E53DC8099056BDC90F7BAC1CC7DFEBAEFB92915C169BB" +
            "C86E2A401837DA5D2B780AD0C7451625797F525FF0965D40D21684886330B5489E828BC2E1A0EC8CC946BCA6CA4064DE" +
            "9C11531234BBFDEBFD40D028C4449BCA3D57CE2A7E9B9CE41C2FEA83C04DB35ADEF74210272B6199171E8F48C7A4E6D6" +
            "518A3E9022772A941AA6889E7A55C1B28FE0C2A3D80B56281525951E6AFA296562CE07DFDD1890DFE6FB16CC0B7A8516" +
            "F22974CEB58C194BDEEC5E8C93EED2F4F1157B8AE87F47E03B962FA28E4018FAA8F24BD98954BD0541458CA0DF463D68" +
            "9A21122053C329357D73C48BE98CCF7A7425D3EA37770D064CF02EF77EE6CE9F8950A52CD678756259B98954C94DC96F" +
            "FC83D3FDC50484D6F58F32D042D8665D05ABC8ABFF436DCA005FC7F72C7038528453D8C615078D25ABD457359ACA3E57" +
            "3EDE81DF615D24C49835E82D9BBB9D7A49ECDF1901C7E103373F11F8857A5A26CC9A816D6084FD057B569EF6BF94CF8F" +
            "A68D7C87C4E3F4091E4957CB6A0B63DC16F78C81C306424F4EA5D848E217B70E5F2D784C6DE1BDFC141313BD41859DDE" +
            "D05277006986B18E22F4C010F60CB96CA8CAFF83FB40A9178993C520E549CCEB6AEB839FD9CAA047EDBE5E6EBF8FDE26" +
            "8DDE4214534F8A1D173E9F69A7EDAEF869C6C35F9A0EAF2C81312B96D549C6810014B2281142E0750A0C25B533B00D01" +
            "3F00FBF7469226128A753DC662B29C5A7F079A6E5B6B3B1552BDC487DA85A4ACEF3C9C742028B870F22F49F08C28B308" +
            "34FC01C5DACD4EBB8D3E425980E403AABC2F49B8FA1C0787F436F4CAFB73B2666B5B7DA79E47C77B246DEA07585480B1" +
            "94EE9AE89B1EC5F1A5744B2131CC59DFE6B40F0308FE6E3872CB4C2A1F493682C523F99F29804AF259E8CD74F29359A9" +
            "50");
    }

    private static ushort ReadUInt16(byte[] source, ref int index)
    {
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(source.AsSpan(index, 2));
        index += 2;
        return value;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> source, ref int index)
    {
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(index, 2));
        index += 2;
        return value;
    }

    private static uint ReadUInt24(ReadOnlySpan<byte> source, ref int index)
    {
        uint value = ((uint)source[index] << 16)
            | ((uint)source[index + 1] << 8)
            | source[index + 2];
        index += 3;
        return value;
    }

    internal static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    internal static byte[] CreateSequentialBytes(byte start, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(start + index));
        }

        return bytes;
    }

    private static void WriteUInt16(Span<byte> destination, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, value);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }
}
