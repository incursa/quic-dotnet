using System.Buffers.Binary;
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
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[0].EncryptionLevel);
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
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, updates[1].EncryptionLevel);
        Assert.Equal(0UL, updates[1].CryptoDataOffset);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, updates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, updates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, updates[4].Kind);

        Span<byte> surfacedServerHello = stackalloc byte[updates[1].CryptoData.Length];
        Assert.True(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
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
    public void UnsupportedClientHelloNamedGroupOrKeyShareFailsDeterministically()
    {
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);
        _ = driver.StartHandshake(CreateBootstrapLocalTransportParameters());

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(
                CreateClientTransportParameters(),
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

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreateClientTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
        };
    }

    private static byte[] CreateClientHelloTranscript(
        QuicTransportParameters transportParameters,
        ushort[]? supportedVersions = null,
        ushort[]? cipherSuites = null,
        ushort keyShareNamedGroup = (ushort)QuicTlsNamedGroup.Secp256r1,
        byte[]? keyShare = null)
    {
        supportedVersions ??= [0x0304];
        cipherSuites ??= [(ushort)QuicTlsCipherSuite.TlsAes128GcmSha256];
        keyShare ??= CreateClientKeyShare();

        byte[] supportedVersionsExtension = CreateClientSupportedVersionsExtension(supportedVersions);
        byte[] keyShareExtension = CreateClientKeyShareExtension(keyShareNamedGroup, keyShare);
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Client);

        int extensionsLength = supportedVersionsExtension.Length
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
        keyShareExtension.CopyTo(body.AsSpan(index));
        index += keyShareExtension.Length;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateMalformedClientHelloTranscript(QuicTransportParameters transportParameters)
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

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateSequentialBytes(byte start, int length)
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
