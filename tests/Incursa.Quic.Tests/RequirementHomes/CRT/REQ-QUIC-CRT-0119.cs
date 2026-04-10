using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0119")]
public sealed class REQ_QUIC_CRT_0119
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleDriverPublishes1RttPacketProtectionMaterialOnlyAfterPeerFinishedProof()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        (byte[] clientHelloTranscript, _) = CreateServerRoleClientHello(peerTransportParameters);
        byte[] localLeafCertificateDer = CreateLocalLeafCertificateDer(localSigningPrivateKey);
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        Assert.Single(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> clientHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHelloTranscript);

        Assert.Equal(9, clientHelloUpdates.Count);
        Assert.False(driver.State.OneRttKeysAvailable);
        Assert.Null(driver.State.OneRttOpenPacketProtectionMaterial);
        Assert.Null(driver.State.OneRttProtectPacketProtectionMaterial);

        FieldInfo keyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsKeySchedule driverKeySchedule = (QuicTlsKeySchedule)keyScheduleField.GetValue(driver)!;
        Assert.True(driverKeySchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] expectedFinishedVerifyData));

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateFinishedTranscript(expectedFinishedVerifyData));

        Assert.Equal(
            $"{QuicTlsUpdateKind.TranscriptProgressed},{QuicTlsUpdateKind.PeerFinishedVerified},{QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable},{QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable},{QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted}",
            string.Join(",", finishedUpdates.Select(update => update.Kind)));
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, finishedUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, finishedUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, finishedUpdates[0].TranscriptPhase);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable, finishedUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable, finishedUpdates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted, finishedUpdates[4].Kind);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.NotNull(driver.State.OneRttOpenPacketProtectionMaterial);
        Assert.NotNull(driver.State.OneRttProtectPacketProtectionMaterial);
        Assert.False(driver.State.OneRttKeysAvailable);
        Assert.False(driver.State.PeerTransportParametersCommitted);
        Assert.Equal(QuicTlsTranscriptPhase.Completed, driver.State.HandshakeTranscriptPhase);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, driver.State.HandshakeMessageType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleBridgeStateRejectsPrematureRepeatedConflictingAndTerminal1RttPublicationDeterministically()
    {
        QuicTransportTlsBridgeState bridge = new(QuicTlsRole.Server);
        QuicTlsPacketProtectionMaterial openMaterial = CreateOneRttMaterial(0x11);
        QuicTlsPacketProtectionMaterial repeatedMaterial = CreateOneRttMaterial(0x11);
        QuicTlsPacketProtectionMaterial conflictingMaterial = CreateOneRttMaterial(0x21);
        QuicTlsPacketProtectionMaterial protectMaterial = CreateOneRttMaterial(0x31);

        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: openMaterial)));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: protectMaterial)));
        Assert.False(bridge.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.False(bridge.OneRttProtectPacketProtectionMaterial.HasValue);

        QuicTransportTlsBridgeState proofedBridge = CreateServerProofedBridgeState();
        Assert.True(proofedBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: openMaterial)));
        Assert.True(proofedBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: protectMaterial)));
        Assert.True(proofedBridge.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(proofedBridge.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.True(proofedBridge.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial currentMaterial));
        Assert.True(currentMaterial.Matches(proofedBridge.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.True(proofedBridge.HasAnyPacketProtectionMaterial);

        Assert.False(proofedBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: repeatedMaterial)));
        Assert.False(proofedBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: conflictingMaterial)));

        QuicTransportTlsBridgeState terminalBridge = CreateServerProofedBridgeState();
        Assert.True(terminalBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.FatalAlert,
            AlertDescription: 0x0032)));
        Assert.True(terminalBridge.IsTerminal);
        Assert.False(terminalBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: openMaterial)));
        Assert.False(terminalBridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: protectMaterial)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleKeepsGenericOneRttPacketProtectionMaterialAndRejectsServerOnlyDirectionalUpdates()
    {
        QuicTransportTlsBridgeState bridge = new();
        QuicTlsPacketProtectionMaterial material = CreateOneRttMaterial(0x51);

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(bridge.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial storedMaterial));
        Assert.True(storedMaterial.Matches(material));

        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.Null(bridge.OneRttOpenPacketProtectionMaterial);
        Assert.Null(bridge.OneRttProtectPacketProtectionMaterial);
    }

    private static QuicTlsPacketProtectionMaterial CreateOneRttMaterial(byte seed)
    {
        byte[] aeadKey = CreateSequentialBytes(seed, 16);
        byte[] aeadIv = CreateSequentialBytes(unchecked((byte)(seed + 0x10)), 12);
        byte[] headerProtectionKey = CreateSequentialBytes(unchecked((byte)(seed + 0x20)), 16);

        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));
        return material;
    }

    private static byte[] CreateLocalLeafCertificateDer(byte[] localSigningPrivateKey)
    {
        using ECDsa localCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        return QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localCertificateKey);
    }

    private static (byte[] ClientHelloTranscript, QuicTlsTranscriptStep ClientHelloStep) CreateServerRoleClientHello(
        QuicTransportParameters peerTransportParameters)
    {
        byte[] clientHello = CreateClientHelloTranscript(peerTransportParameters);
        QuicTlsTranscriptProgress progress = new(QuicTlsRole.Server);
        progress.AppendCryptoBytes(0, clientHello);
        QuicTlsTranscriptStep clientHelloStep = progress.Advance(QuicTlsRole.Server);

        Assert.Equal(QuicTlsTranscriptStepKind.PeerTransportParametersStaged, clientHelloStep.Kind);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, clientHelloStep.TranscriptPhase);
        return (clientHello, clientHelloStep);
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

    private static QuicTransportTlsBridgeState CreateServerProofedBridgeState()
    {
        QuicTransportTlsBridgeState bridge = new(QuicTlsRole.Server);

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: CreateBootstrapLocalTransportParameters())));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ClientHello,
            HandshakeMessageLength: 96,
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            TransportParameters: CreateClientTransportParameters(),
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 32,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));

        return bridge;
    }

    private static byte[] CreateClientHelloTranscript(QuicTransportParameters transportParameters)
    {
        byte[] supportedVersionsExtension = CreateClientSupportedVersionsExtension();
        byte[] keyShareExtension = CreateClientKeyShareExtension();
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

        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256);
        index += 2;

        body[index++] = 1;
        body[index++] = 0x00;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;
        supportedVersionsExtension.CopyTo(body.AsSpan(index));
        index += supportedVersionsExtension.Length;
        keyShareExtension.CopyTo(body.AsSpan(index));
        index += keyShareExtension.Length;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateClientSupportedVersionsExtension()
    {
        byte[] extension = new byte[7];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x002b);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), 3);
        index += 2;
        extension[index++] = 2;
        WriteUInt16(extension.AsSpan(index, 2), 0x0304);
        return extension;
    }

    private static byte[] CreateClientKeyShareExtension()
    {
        byte[] keyShare = CreateClientKeyShare();
        byte[] extension = new byte[2 + 2 + 2 + 2 + 2 + keyShare.Length];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)(2 + 2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)(2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)QuicTlsNamedGroup.Secp256r1);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), (ushort)keyShare.Length);
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
            D = CreateScalar(1),
        });

        ECParameters parameters = clientKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[1 + (2 * 32)];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] CreateTransportParametersExtension(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            senderRole,
            encodedTransportParameters,
            out int transportParametersBytesWritten));

        byte[] extension = new byte[4 + transportParametersBytesWritten];
        WriteUInt16(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)transportParametersBytesWritten);
        encodedTransportParameters.AsSpan(0, transportParametersBytesWritten).CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static byte[] CreateFinishedTranscript(ReadOnlySpan<byte> verifyData)
    {
        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Finished, verifyData);
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
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
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
        BinaryPrimitives.WriteUInt16BigEndian(destination, value);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }
}
