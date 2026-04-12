using BenchmarkDotNet.Attributes;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the client Finished publication path that derives and surfaces the first application packet-protection material.
/// </summary>
[MemoryDiagnoser]
public class QuicTlsClientFinishedPublicationBenchmarks
{
    private byte[] localHandshakePrivateKey = [];
    private byte[] leafCertificateDer = [];
    private byte[] pinnedPeerLeafCertificateSha256 = [];
    private QuicTransportParameters localTransportParameters = default!;
    private QuicTransportParameters peerTransportParameters = default!;
    private byte[] clientHelloTranscript = [];
    private byte[] serverHelloTranscript = [];
    private byte[] encryptedExtensionsTranscript = [];
    private byte[] certificateTranscript = [];
    private byte[] certificateVerifyTranscript = [];
    private byte[] finishedTranscript = [];
    private QuicTlsTransportBridgeDriver driver = default!;

    /// <summary>
    /// Prepares a representative client-handshake boundary and the Finished transcript used by the benchmark.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        localHandshakePrivateKey = CreateScalar(0x11);
        localTransportParameters = CreateBootstrapLocalTransportParameters();
        peerTransportParameters = CreateServerTransportParameters();

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        leafCertificateDer = CreateLeafCertificateDer(leafKey);
        pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        clientHelloTranscript = PrepareClientHelloTranscript();
        (
            serverHelloTranscript,
            encryptedExtensionsTranscript,
            certificateTranscript,
            certificateVerifyTranscript,
            finishedTranscript) = PrepareClientHandshakeTranscriptParts(
            clientHelloTranscript,
            localHandshakePrivateKey,
            peerTransportParameters,
            leafKey,
            leafCertificateDer);
    }

    /// <summary>
    /// Rebuilds the deterministic client-handshake state to the boundary immediately before peer Finished is processed.
    /// </summary>
    [IterationSetup]
    public void IterationSetup()
    {
        driver = new QuicTlsTransportBridgeDriver(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        _ = driver.StartHandshake(localTransportParameters);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, serverHelloTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, encryptedExtensionsTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, certificateTranscript);
        _ = driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, certificateVerifyTranscript);
    }

    /// <summary>
    /// Measures the client Finished publication step that surfaces the explicit 1-RTT readiness boundary.
    /// </summary>
    [Benchmark]
    public int PublishClientFinishedMaterial()
    {
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        return updates.Count;
    }

    private byte[] PrepareClientHelloTranscript()
    {
        QuicTlsTransportBridgeDriver tempDriver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = tempDriver.StartHandshake(localTransportParameters);
        if (bootstrapUpdates.Count != 2)
        {
            throw new InvalidOperationException("Failed to prepare the representative client ClientHello transcript.");
        }

        return bootstrapUpdates[1].CryptoData.ToArray();
    }

    private static (
        byte[] ServerHelloTranscript,
        byte[] EncryptedExtensionsTranscript,
        byte[] CertificateTranscript,
        byte[] CertificateVerifyTranscript,
        byte[] FinishedTranscript) PrepareClientHandshakeTranscriptParts(
        ReadOnlyMemory<byte> clientHelloTranscript,
        ReadOnlyMemory<byte> localHandshakePrivateKey,
        QuicTransportParameters peerTransportParameters,
        ECDsa leafKey,
        byte[] leafCertificateDer)
    {
        QuicTlsKeySchedule schedule = new(localHandshakePrivateKey);
        schedule.AppendLocalHandshakeMessage(clientHelloTranscript.Span);

        byte[] serverHello = CreateServerHelloTranscript();
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(peerTransportParameters);
        byte[] certificate = CreateCertificateTranscript(leafCertificateDer);
        byte[] certificateVerifyTranscriptHash = SHA256.HashData([
            .. clientHelloTranscript.Span,
            .. serverHello,
            .. encryptedExtensions,
            .. certificate,
        ]);
        byte[] certificateVerify = CreateCertificateVerifyTranscript(
            leafKey,
            certificateVerifyTranscriptHash);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = schedule.ProcessTranscriptStep(CreateServerHelloStep(serverHello));
        if (serverHelloUpdates.Count != 3)
        {
            throw new InvalidOperationException("Failed to prepare the representative serverHello transcript.");
        }

        if (!schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] serverHelloOnlyVerifyData))
        {
            throw new InvalidOperationException("Failed to prepare the representative Finished transcript.");
        }

        _ = schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters));
        _ = schedule.ProcessTranscriptStep(CreateCertificateStep(leafCertificateDer));
        _ = schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(certificateVerify));

        if (!schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] finishedVerifyData))
        {
            throw new InvalidOperationException("Failed to prepare the representative Finished transcript.");
        }

        if (serverHelloOnlyVerifyData.SequenceEqual(finishedVerifyData))
        {
            throw new InvalidOperationException("Failed to prepare a distinct Finished transcript.");
        }

        return (
            serverHello,
            encryptedExtensions,
            certificate,
            certificateVerify,
            CreateFinishedTranscript(finishedVerifyData));
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
        byte[] transcriptBytes = CreateCertificateTranscript(leafCertificateDer);
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

    private static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
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

    private static byte[] CreateEncryptedExtensionsTranscript(QuicTransportParameters transportParameters)
    {
        byte[] encodedTransportParameters = new byte[256];
        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server,
            encodedTransportParameters,
            out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to format the representative transport parameters.");
        }

        if (!QuicTransportParametersCodec.TryParseTransportParameters(
            encodedTransportParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters))
        {
            throw new InvalidOperationException("Failed to parse the representative transport parameters.");
        }

        byte[] transcript = new byte[512];
        if (!QuicTlsTranscriptProgress.TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
            parsedTransportParameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int messageBytesWritten))
        {
            throw new InvalidOperationException("Failed to format the representative EncryptedExtensions transcript.");
        }

        Array.Resize(ref transcript, messageBytesWritten);
        return transcript;
    }

    private static byte[] CreateLeafCertificateDer(ECDsa leafKey)
    {
        CertificateRequest request = new(
            "CN=Incursa.Quic Benchmark Leaf",
            leafKey,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        return certificate.Export(X509ContentType.Cert);
    }

    private static byte[] CreateCertificateTranscript(ReadOnlySpan<byte> leafCertificateDer)
    {
        const int UInt16Length = 2;
        const int UInt24Length = 3;

        if (leafCertificateDer.IsEmpty)
        {
            throw new ArgumentException("The leaf certificate must not be empty.", nameof(leafCertificateDer));
        }

        int certificateEntryLength = checked(UInt24Length + leafCertificateDer.Length + UInt16Length);
        byte[] body = new byte[1 + UInt24Length + certificateEntryLength];
        int index = 0;

        body[index++] = 0x00;
        WriteUInt24(body.AsSpan(index, UInt24Length), certificateEntryLength);
        index += UInt24Length;

        WriteUInt24(body.AsSpan(index, UInt24Length), leafCertificateDer.Length);
        index += UInt24Length;
        leafCertificateDer.CopyTo(body.AsSpan(index, leafCertificateDer.Length));
        index += leafCertificateDer.Length;

        WriteUInt16(body.AsSpan(index, UInt16Length), 0);

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Certificate, body);
    }

    private static byte[] CreateCertificateVerifyTranscript(
        ECDsa leafKey,
        ReadOnlySpan<byte> transcriptHash,
        QuicTlsSignatureScheme signatureScheme = QuicTlsSignatureScheme.EcdsaSecp256r1Sha256,
        DSASignatureFormat signatureFormat = DSASignatureFormat.Rfc3279DerSequence)
    {
        byte[] signature = CreateCertificateVerifySignature(leafKey, transcriptHash, signatureFormat);
        byte[] body = new byte[2 + 2 + signature.Length];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), (ushort)signatureScheme);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)signature.Length);
        index += 2;
        signature.CopyTo(body.AsSpan(index, signature.Length));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.CertificateVerify, body);
    }

    private static byte[] CreateCertificateVerifySignature(
        ECDsa leafKey,
        ReadOnlySpan<byte> transcriptHash,
        DSASignatureFormat signatureFormat = DSASignatureFormat.Rfc3279DerSequence)
    {
        ArgumentNullException.ThrowIfNull(leafKey);

        const int CertificateVerifySignedDataPrefixLength = 64;
        byte[] serverCertificateVerifyContext = Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify");
        Span<byte> signedData = stackalloc byte[CertificateVerifySignedDataPrefixLength
            + serverCertificateVerifyContext.Length
            + 1
            + transcriptHash.Length];
        signedData[..CertificateVerifySignedDataPrefixLength].Fill(0x20);
        serverCertificateVerifyContext.CopyTo(signedData.Slice(CertificateVerifySignedDataPrefixLength));
        signedData[CertificateVerifySignedDataPrefixLength + serverCertificateVerifyContext.Length] = 0x00;
        transcriptHash.CopyTo(
            signedData.Slice(CertificateVerifySignedDataPrefixLength + serverCertificateVerifyContext.Length + 1));

        return leafKey.SignData(signedData, HashAlgorithmName.SHA256, signatureFormat);
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
        destination[0] = checked((byte)((value >> 16) & 0xFF));
        destination[1] = checked((byte)((value >> 8) & 0xFF));
        destination[2] = checked((byte)(value & 0xFF));
    }
}
