using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0109")]
public sealed class REQ_QUIC_CRT_0109
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleDriverRequiresPeerFinishedVerificationBeforeCommittingPeerTransportParameters()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Client, localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.NotEmpty(driver.StartHandshake(localTransportParameters));

        (byte[] prefixTranscript, byte[] finishedTranscript) = CreateClientHandshakeTranscriptParts(
            localHandshakePrivateKey,
            peerTransportParameters);

        IReadOnlyList<QuicTlsStateUpdate> prefixUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            prefixTranscript);

        Assert.Equal(8, prefixUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, prefixUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, prefixUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, prefixUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, prefixUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, prefixUpdates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, prefixUpdates[4].Kind);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, prefixUpdates[5].Kind);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, prefixUpdates[6].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificateVerifyVerified, prefixUpdates[7].Kind);
        Assert.True(driver.State.PeerCertificateVerifyVerified);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        Assert.Equal(3, finishedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, finishedUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, finishedUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted, finishedUpdates[2].Kind);
        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> commitUpdates = driver.CommitPeerTransportParameters(peerTransportParameters);
        Assert.Single(commitUpdates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersCommitted, commitUpdates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersCommitted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TamperedPeerFinishedFailsDeterministicallyAndBlocksCommitProgression()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Client, localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.NotEmpty(driver.StartHandshake(localTransportParameters));

        (byte[] prefixTranscript, byte[] finishedTranscript) = CreateClientHandshakeTranscriptParts(
            localHandshakePrivateKey,
            peerTransportParameters);

        Assert.NotEmpty(driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, prefixTranscript));

        byte[] tamperedFinishedTranscript = finishedTranscript.ToArray();
        tamperedFinishedTranscript[^1] ^= 0x80;

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            tamperedFinishedTranscript);

        Assert.NotEmpty(finishedUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, finishedUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, finishedUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, finishedUpdates[^1].Kind);
        Assert.Equal((ushort)0x0033, finishedUpdates[^1].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleCommitRemainsUnavailableWithoutEquivalentCryptoCoverage()
    {
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreateClientTransportParameters();
        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Server);

        Assert.NotEmpty(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateClientHelloTranscript(peerTransportParameters));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.NotNull(updates[0].TransportParameters);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));
    }

    private static (byte[] PrefixTranscript, byte[] FinishedTranscript) CreateClientHandshakeTranscriptParts(
        ReadOnlyMemory<byte> localHandshakePrivateKey,
        QuicTransportParameters peerTransportParameters)
    {
        QuicTlsKeySchedule schedule = new(localHandshakePrivateKey);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);

        byte[] serverHello = CreateServerHelloTranscript(
            QuicTlsCipherSuite.TlsAes128GcmSha256,
            CreateServerKeyShare());
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(peerTransportParameters);
        byte[] certificate = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(leafCertificateDer);
        byte[] certificateVerifyTranscriptHash = SHA256.HashData([
            .. serverHello,
            .. encryptedExtensions,
            .. certificate,
        ]);
        byte[] certificateVerify = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            certificateVerifyTranscriptHash);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = schedule.ProcessTranscriptStep(CreateServerHelloStep(serverHello));
        Assert.Equal(3, serverHelloUpdates.Count);
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] serverHelloOnlyVerifyData));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(leafCertificateDer)));
        Assert.Single(schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(certificateVerify)));
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] finishedVerifyData));
        Assert.False(serverHelloOnlyVerifyData.SequenceEqual(finishedVerifyData));

        byte[] prefixTranscript = new byte[
            serverHello.Length
            + encryptedExtensions.Length
            + certificate.Length
            + certificateVerify.Length];
        int index = 0;

        serverHello.CopyTo(prefixTranscript.AsSpan(index));
        index += serverHello.Length;
        encryptedExtensions.CopyTo(prefixTranscript.AsSpan(index));
        index += encryptedExtensions.Length;
        certificate.CopyTo(prefixTranscript.AsSpan(index));
        index += certificate.Length;
        certificateVerify.CopyTo(prefixTranscript.AsSpan(index));

        return (prefixTranscript, CreateFinishedTranscript(finishedVerifyData));
    }

    private static QuicTlsTranscriptStep CreateServerHelloStep(byte[] transcriptBytes)
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            NamedGroup: QuicTlsNamedGroup.Secp256r1,
            KeyShare: CreateServerKeyShare(),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateEncryptedExtensionsStep(QuicTransportParameters transportParameters)
    {
        byte[] transcriptBytes = CreateEncryptedExtensionsTranscript(transportParameters);
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.PeerTransportParametersStaged,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            TransportParameters: transportParameters,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateCertificateStep(byte[] leafCertificateDer)
    {
        byte[] transcriptBytes = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(leafCertificateDer);
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Certificate,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateCertificateVerifyStep(
        ECDsa leafKey,
        ReadOnlySpan<byte> transcriptHash)
    {
        byte[] transcriptBytes = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            transcriptHash);
        return CreateCertificateVerifyStep(transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateCertificateVerifyStep(byte[] transcriptBytes)
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
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
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    private static QuicTransportParameters CreateServerTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 9443,
                IPv6Address = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
                IPv6Port = 9553,
                ConnectionId = [0x44, 0x55],
                StatelessResetToken = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F],
            },
            ActiveConnectionIdLimit = 4,
        };
    }

    private static byte[] CreateClientHelloTranscript(QuicTransportParameters transportParameters)
    {
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Client);

        byte[] body = new byte[43 + transportParametersExtension.Length];
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

        WriteUInt16(body.AsSpan(index, 2), (ushort)transportParametersExtension.Length);
        index += 2;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateServerHelloTranscript(
        QuicTlsCipherSuite cipherSuite,
        byte[] keyShare)
    {
        int extensionsLength = 6 + 4 + 2 + 2 + keyShare.Length;
        byte[] body = new byte[40 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;

        CreateSequentialBytes(0x40, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;

        body[index++] = 0;
        WriteUInt16(body.AsSpan(index, 2), (ushort)cipherSuite);
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

    private static byte[] CreateEncryptedExtensionsTranscript(QuicTransportParameters transportParameters)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server,
            encodedTransportParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));

        byte[] transcript = new byte[512];
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicTransportParametersMessage(
            parsedTransportParameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int messageBytesWritten));

        Array.Resize(ref transcript, messageBytesWritten);
        return transcript;
    }

    private static byte[] CreateFinishedTranscript(ReadOnlySpan<byte> verifyData)
    {
        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Finished, verifyData);
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

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
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
}
