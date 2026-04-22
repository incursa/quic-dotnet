using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0112")]
public sealed class REQ_QUIC_CRT_0112
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleKeySchedulePublishesServerHelloBeforeHandshakeKeys()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server);
        byte[] clientHello = CreateClientHelloTranscript(CreateClientTransportParameters());

        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);
        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, clientHelloStep.Kind);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, clientHelloStep.TranscriptPhase);

        QuicTlsKeySchedule schedule = new(QuicTlsRole.Server, localHandshakePrivateKey);
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

        QuicTlsTranscriptProgress serverHelloProgress = new(QuicTlsRole.Client);
        serverHelloProgress.AppendCryptoBytes(0, updates[0].CryptoData.ToArray());
        QuicTlsTranscriptStep serverHelloStep = serverHelloProgress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, serverHelloStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloStep.HandshakeMessageType);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, serverHelloStep.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, serverHelloStep.TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsNamedGroup.Secp256r1, serverHelloStep.NamedGroup);
        Assert.False(serverHelloStep.KeyShare.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleDriverAcceptsSupportedClientHelloConstructsServerHelloAndPublishesHandshakeKeys()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey);

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
        Assert.Single(bootstrapUpdates);
        Assert.Equal(QuicTlsUpdateKind.LocalTransportParametersReady, bootstrapUpdates[0].Kind);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.True(updates.Count >= 5);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, updates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, updates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, updates[0].TranscriptHashAlgorithm);
        Assert.NotNull(updates[0].TransportParameters);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, updates[1].EncryptionLevel);
        Assert.Equal(0UL, updates[1].CryptoDataOffset);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, updates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, updates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, updates[4].Kind);

        Span<byte> surfacedServerHello = stackalloc byte[updates[1].CryptoData.Length];
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
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, driver.State.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, driver.State.TranscriptHashAlgorithm);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.True(driver.State.TryGetHandshakeOpenPacketProtectionMaterial(out _));
        Assert.True(driver.State.TryGetHandshakeProtectPacketProtectionMaterial(out _));
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));
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
    public void UnsupportedClientHelloNamedGroupWithoutAdvertisedSecp256r1SupportFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
                supportedGroups: [0x001d],
                keyShareNamedGroup: 0x001d,
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
        byte[]? keyShare = null)
    {
        supportedVersions ??= [0x0304];
        cipherSuites ??= [(ushort)QuicTlsCipherSuite.TlsAes128GcmSha256];
        supportedGroups ??= [(ushort)QuicTlsNamedGroup.Secp256r1];
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

        return $"0x{extensionType:X4}";
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
