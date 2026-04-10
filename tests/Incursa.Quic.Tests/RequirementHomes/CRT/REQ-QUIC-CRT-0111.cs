using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0111")]
public sealed class REQ_QUIC_CRT_0111
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BridgeStateRequiresExplicitPolicyAcceptanceBeforeCommit()
    {
        QuicTransportParameters localParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerParameters = CreatePeerTransportParameters();

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
            TransportParameters: peerParameters,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)));
        Assert.False(bridge.PeerCertificatePolicyAccepted);
        Assert.False(bridge.CanCommitPeerTransportParameters(peerParameters));
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificatePolicyAccepted)));
        Assert.True(bridge.PeerCertificatePolicyAccepted);
        Assert.False(bridge.CanCommitPeerTransportParameters(peerParameters));

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.TranscriptProgressed,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Finished,
            HandshakeMessageLength: 48,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)));
        Assert.True(bridge.CanCommitPeerTransportParameters(peerParameters));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersCommitted,
            TransportParameters: peerParameters)));

        Assert.True(bridge.PeerTransportParametersCommitted);
        Assert.True(bridge.PeerCertificatePolicyAccepted);
        Assert.True(bridge.PeerFinishedVerified);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleDriverPublishesPolicyAcceptanceOnlyForThePinnedLeafFingerprint()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] certificateTranscript,
            byte[] certificateVerifyTranscript,
            byte[] finishedTranscript,
            byte[] pinnedPeerLeafCertificateSha256) = CreateClientHandshakeTranscriptParts(
            localHandshakePrivateKey,
            peerTransportParameters);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        Assert.NotEmpty(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverHelloTranscript);

        Assert.Equal(4, serverHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, serverHelloUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, serverHelloUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, serverHelloUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, serverHelloUpdates[3].Kind);

        IReadOnlyList<QuicTlsStateUpdate> encryptedExtensionsUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            encryptedExtensionsTranscript);

        Assert.Single(encryptedExtensionsUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, encryptedExtensionsUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, encryptedExtensionsUpdates[0].HandshakeMessageType);

        IReadOnlyList<QuicTlsStateUpdate> certificateUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateTranscript);

        Assert.Single(certificateUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, certificateUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Certificate, certificateUpdates[0].HandshakeMessageType);

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateVerifyTranscript);

        Assert.Equal(3, certificateVerifyUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, certificateVerifyUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.CertificateVerify, certificateVerifyUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificateVerifyVerified, certificateVerifyUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificatePolicyAccepted, certificateVerifyUpdates[2].Kind);
        Assert.True(driver.State.PeerCertificatePolicyAccepted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        Assert.Equal(3, finishedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted, finishedUpdates[2].Kind);
        Assert.True(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> commitUpdates = driver.CommitPeerTransportParameters(peerTransportParameters);
        Assert.Single(commitUpdates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersCommitted, commitUpdates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersCommitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverLeavesPeerCertificateUnacceptedWhenNoPolicyIsConfigured()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] certificateTranscript,
            byte[] certificateVerifyTranscript,
            byte[] finishedTranscript,
            _) = CreateClientHandshakeTranscriptParts(
            localHandshakePrivateKey,
            peerTransportParameters);

        QuicTlsTransportBridgeDriver driver = new(QuicTlsRole.Client, localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.NotEmpty(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverHelloTranscript);

        Assert.Equal(4, serverHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, serverHelloUpdates[3].Kind);

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            encryptedExtensionsTranscript));

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateTranscript));

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateVerifyTranscript);

        Assert.Equal(2, certificateVerifyUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificateVerifyVerified, certificateVerifyUpdates[1].Kind);
        Assert.False(driver.State.PeerCertificatePolicyAccepted);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        Assert.Equal(3, finishedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));
        Assert.False(driver.State.IsTerminal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleDriverRejectsMismatchedPinnedFingerprintsDeterministically()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] certificateTranscript,
            byte[] certificateVerifyTranscript,
            byte[] finishedTranscript,
            byte[] pinnedPeerLeafCertificateSha256) = CreateClientHandshakeTranscriptParts(
            localHandshakePrivateKey,
            peerTransportParameters);
        pinnedPeerLeafCertificateSha256[0] ^= 0x80;

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        Assert.NotEmpty(driver.StartHandshake(localTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverHelloTranscript);

        Assert.Equal(4, serverHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, serverHelloUpdates[3].Kind);

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            encryptedExtensionsTranscript));

        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateTranscript));

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateVerifyTranscript);

        Assert.Equal(3, certificateVerifyUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificateVerifyVerified, certificateVerifyUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, certificateVerifyUpdates[2].Kind);
        Assert.Equal((ushort)0x0031, certificateVerifyUpdates[2].AlertDescription);
        Assert.True(driver.State.IsTerminal);
        Assert.False(driver.State.PeerCertificatePolicyAccepted);
        Assert.False(driver.State.PeerFinishedVerified);
        Assert.False(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
        Assert.Empty(driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, finishedTranscript));
        Assert.Empty(driver.CommitPeerTransportParameters(peerTransportParameters));
    }

    private static (
        byte[] ServerHelloTranscript,
        byte[] EncryptedExtensionsTranscript,
        byte[] CertificateTranscript,
        byte[] CertificateVerifyTranscript,
        byte[] FinishedTranscript,
        byte[] PinnedPeerLeafCertificateSha256) CreateClientHandshakeTranscriptParts(
        ReadOnlyMemory<byte> localHandshakePrivateKey,
        QuicTransportParameters peerTransportParameters)
    {
        QuicTlsKeySchedule schedule = new(localHandshakePrivateKey);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] leafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        byte[] serverHello = CreateServerHelloTranscript();
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

        return (
            serverHello,
            encryptedExtensions,
            certificate,
            certificateVerify,
            CreateFinishedTranscript(finishedVerifyData),
            leafCertificateSha256);
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

    private static QuicTlsTranscriptStep CreateCertificateVerifyStep(byte[] certificateVerifyTranscript)
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: (uint)(certificateVerifyTranscript.Length - 4),
            HandshakeMessageBytes: certificateVerifyTranscript);
    }

    private static byte[] CreateFinishedTranscript(ReadOnlySpan<byte> verifyData)
    {
        byte[] transcript = new byte[4 + verifyData.Length];
        transcript[0] = (byte)QuicTlsHandshakeMessageType.Finished;
        WriteUInt24(transcript.AsSpan(1, 3), verifyData.Length);
        verifyData.CopyTo(transcript.AsSpan(4));
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

    private static byte[] CreateEncryptedExtensionsTranscript(QuicTransportParameters transportParameters)
    {
        byte[] encodedTransportParameters = CreateFormattedTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));

        byte[] transcript = new byte[512];
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
            parsedTransportParameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int bytesWritten));

        Array.Resize(ref transcript, bytesWritten);
        return transcript;
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

    private static byte[] CreateFormattedTransportParameters(QuicTransportParameters parameters, QuicTransportParameterRole role)
    {
        Span<byte> transcript = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            role,
            transcript,
            out int bytesWritten));

        byte[] formatted = new byte[bytesWritten];
        transcript[..bytesWritten].CopyTo(formatted);
        return formatted;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        Array.Fill(scalar, value);
        return scalar;
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
                IPv4Address = [203, 0, 113, 7],
                IPv4Port = 9443,
                IPv6Address = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
                IPv6Port = 9553,
                ConnectionId = [0x44, 0x55],
                StatelessResetToken = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F],
            },
        };
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

    private static byte[] CreateSequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(seed + index));
        }

        return bytes;
    }
}
