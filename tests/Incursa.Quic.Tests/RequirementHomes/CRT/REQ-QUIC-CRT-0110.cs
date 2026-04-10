using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0110")]
public sealed class REQ_QUIC_CRT_0110
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleManagedCertificateVerifyProofSucceedsForTheSupportedLeafSubset()
    {
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        ProofInputs inputs = CreateProofInputs(peerTransportParameters);
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        using ECDsa leafKey = inputs.LeafKey;

        Assert.Equal(3, schedule.ProcessTranscriptStep(CreateServerHelloStep(inputs.ServerHelloTranscript)).Count);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(inputs.CertificateTranscript)));

        byte[] certificateVerifyTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            inputs.CertificateVerifyTranscriptHash);

        IReadOnlyList<QuicTlsStateUpdate> certificateVerifyUpdates = schedule.ProcessTranscriptStep(
            CreateCertificateVerifyStep(certificateVerifyTranscript));

        Assert.Single(certificateVerifyUpdates);
        Assert.Equal(QuicTlsUpdateKind.PeerCertificateVerifyVerified, certificateVerifyUpdates[0].Kind);
        Assert.True(schedule.PeerCertificateVerifyVerified);
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out _));
        Assert.False(schedule.PeerFinishedVerified);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnsupportedCertificateVerifySignatureSchemeFailsDeterministically()
    {
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        ProofInputs inputs = CreateProofInputs(peerTransportParameters);
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        using ECDsa leafKey = inputs.LeafKey;

        Assert.Equal(3, schedule.ProcessTranscriptStep(CreateServerHelloStep(inputs.ServerHelloTranscript)).Count);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(inputs.CertificateTranscript)));

        byte[] certificateVerifyTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            inputs.CertificateVerifyTranscriptHash,
            signatureScheme: unchecked((QuicTlsSignatureScheme)0x0503));

        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            CreateCertificateVerifyStep(certificateVerifyTranscript));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.False(schedule.PeerCertificateVerifyVerified);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(certificateVerifyTranscript)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedLeafCertificatePayloadFailsDeterministically()
    {
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        ProofInputs inputs = CreateProofInputs(peerTransportParameters);
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        using ECDsa leafKey = inputs.LeafKey;

        Assert.Equal(3, schedule.ProcessTranscriptStep(CreateServerHelloStep(inputs.ServerHelloTranscript)).Count);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));

        byte[] malformedCertificateTranscript = inputs.CertificateTranscript[..^1];
        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            CreateCertificateStep(malformedCertificateTranscript));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.False(schedule.PeerCertificateVerifyVerified);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(
            QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
                leafKey,
                inputs.CertificateVerifyTranscriptHash))));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedCertificateVerifyPayloadFailsDeterministically()
    {
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        ProofInputs inputs = CreateProofInputs(peerTransportParameters);
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        using ECDsa leafKey = inputs.LeafKey;

        Assert.Equal(3, schedule.ProcessTranscriptStep(CreateServerHelloStep(inputs.ServerHelloTranscript)).Count);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(inputs.CertificateTranscript)));

        byte[] malformedCertificateVerifyTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            inputs.CertificateVerifyTranscriptHash)[..^1];

        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            CreateCertificateVerifyStep(malformedCertificateVerifyTranscript));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.False(schedule.PeerCertificateVerifyVerified);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidCertificateVerifySignatureFailsDeterministically()
    {
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        ProofInputs inputs = CreateProofInputs(peerTransportParameters);
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        using ECDsa leafKey = inputs.LeafKey;

        Assert.Equal(3, schedule.ProcessTranscriptStep(CreateServerHelloStep(inputs.ServerHelloTranscript)).Count);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(inputs.CertificateTranscript)));

        byte[] certificateVerifyTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            inputs.CertificateVerifyTranscriptHash);
        certificateVerifyTranscript[^1] ^= 0x01;

        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            CreateCertificateVerifyStep(certificateVerifyTranscript));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0033, updates[0].AlertDescription);
        Assert.False(schedule.PeerCertificateVerifyVerified);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void P1363EncodedCertificateVerifySignatureFailsDeterministically()
    {
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        ProofInputs inputs = CreateProofInputs(peerTransportParameters);
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        using ECDsa leafKey = inputs.LeafKey;

        Assert.Equal(3, schedule.ProcessTranscriptStep(CreateServerHelloStep(inputs.ServerHelloTranscript)).Count);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(inputs.CertificateTranscript)));

        byte[] certificateVerifyTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            inputs.CertificateVerifyTranscriptHash,
            signatureFormat: DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            CreateCertificateVerifyStep(certificateVerifyTranscript));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0033, updates[0].AlertDescription);
        Assert.False(schedule.PeerCertificateVerifyVerified);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(certificateVerifyTranscript)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TranscriptMismatchFailsDeterministically()
    {
        QuicTransportParameters signedPeerTransportParameters = CreateServerTransportParameters();
        QuicTransportParameters transcriptPeerTransportParameters = CreateServerTransportParameters();
        transcriptPeerTransportParameters.MaxIdleTimeout = 31;

        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] signedServerHelloTranscript = CreateServerHelloTranscript();
        byte[] signedEncryptedExtensionsTranscript = CreateEncryptedExtensionsTranscript(signedPeerTransportParameters);
        byte[] transcriptServerHelloTranscript = CreateServerHelloTranscript();
        byte[] certificateTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(leafCertificateDer);
        byte[] signedCertificateVerifyTranscriptHash = SHA256.HashData([
            .. signedServerHelloTranscript,
            .. signedEncryptedExtensionsTranscript,
            .. certificateTranscript,
        ]);

        Assert.Equal(3, schedule.ProcessTranscriptStep(CreateServerHelloStep(transcriptServerHelloTranscript)).Count);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(transcriptPeerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(certificateTranscript)));

        byte[] certificateVerifyTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            signedCertificateVerifyTranscriptHash);

        IReadOnlyList<QuicTlsStateUpdate> updates = schedule.ProcessTranscriptStep(
            CreateCertificateVerifyStep(certificateVerifyTranscript));

        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0033, updates[0].AlertDescription);
        Assert.False(schedule.PeerCertificateVerifyVerified);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FatalCryptoStateBlocksLaterProofProgression()
    {
        QuicTransportParameters peerTransportParameters = CreateServerTransportParameters();
        ProofInputs inputs = CreateProofInputs(peerTransportParameters);
        QuicTlsKeySchedule schedule = new(CreateScalar(0x11));

        using ECDsa leafKey = inputs.LeafKey;

        Assert.Equal(3, schedule.ProcessTranscriptStep(CreateServerHelloStep(inputs.ServerHelloTranscript)).Count);
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));

        byte[] malformedCertificateTranscript = inputs.CertificateTranscript[..^1];
        Assert.Single(schedule.ProcessTranscriptStep(CreateCertificateStep(malformedCertificateTranscript)));
        Assert.False(schedule.PeerCertificateVerifyVerified);

        byte[] validCertificateVerifyTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            inputs.CertificateVerifyTranscriptHash);

        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(validCertificateVerifyTranscript)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(inputs.CertificateTranscript)));
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

    private static QuicTlsTranscriptStep CreateCertificateStep(byte[] transcriptBytes)
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Certificate,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
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

    private static ProofInputs CreateProofInputs(QuicTransportParameters transportParameters)
    {
        ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] serverHelloTranscript = CreateServerHelloTranscript();
        byte[] encryptedExtensionsTranscript = CreateEncryptedExtensionsTranscript(transportParameters);
        byte[] certificateTranscript = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(leafCertificateDer);
        byte[] certificateVerifyTranscriptHash = SHA256.HashData([
            .. serverHelloTranscript,
            .. encryptedExtensionsTranscript,
            .. certificateTranscript,
        ]);

        return new ProofInputs(
            leafKey,
            leafCertificateDer,
            serverHelloTranscript,
            encryptedExtensionsTranscript,
            certificateTranscript,
            certificateVerifyTranscriptHash);
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
            out QuicTransportParameters parsedParameters));

        byte[] transcript = new byte[512];
        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
            parsedParameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int bytesWritten));

        Array.Resize(ref transcript, bytesWritten);
        return transcript;
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

    private sealed record ProofInputs(
        ECDsa LeafKey,
        byte[] LeafCertificateDer,
        byte[] ServerHelloTranscript,
        byte[] EncryptedExtensionsTranscript,
        byte[] CertificateTranscript,
        byte[] CertificateVerifyTranscriptHash);
}
