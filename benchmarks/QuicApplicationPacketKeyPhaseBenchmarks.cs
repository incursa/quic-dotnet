using System.Buffers.Binary;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks successor 1-RTT packet-protection install plus 1-RTT short-header packet formatting and opening when the short-header Key Phase bit is preserved.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationPacketKeyPhaseBenchmarks
{
    private static readonly byte[] DestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private byte[] localHandshakePrivateKey = [];
    private byte[] localSigningPrivateKey = [];
    private byte[] leafCertificateDer = [];
    private byte[] pinnedPeerLeafCertificateSha256 = [];
    private QuicTransportParameters localTransportParameters = default!;
    private QuicTransportParameters peerTransportParameters = default!;
    private byte[] clientHelloTranscript = [];
    private QuicTlsTransportBridgeDriver installDriver = default!;
    private QuicHandshakeFlowCoordinator packetCoordinator = default!;
    private QuicTlsPacketProtectionMaterial installedOpenPacketProtectionMaterial;
    private QuicTlsPacketProtectionMaterial installedProtectPacketProtectionMaterial;
    private readonly byte[] applicationPayload = new byte[1];
    private byte[] protectedPacket = [];

    /// <summary>
    /// Prepares representative 1-RTT packet-protection material, the successor install state, and the protected packet used by the open benchmark.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        localHandshakePrivateKey = CreateScalar(0x11);
        localSigningPrivateKey = CreateScalar(0x44);
        localTransportParameters = CreateBootstrapLocalTransportParameters();
        peerTransportParameters = CreateServerTransportParameters();

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        leafKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        leafCertificateDer = CreateLeafCertificateDer(leafKey);
        pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        if (!QuicFrameCodec.TryFormatPingFrame(applicationPayload, out int bytesWritten) || bytesWritten <= 0)
        {
            throw new InvalidOperationException("Failed to prepare representative 1-RTT application payload.");
        }

        clientHelloTranscript = PrepareClientHelloTranscript();

        QuicTlsTransportBridgeDriver tempDriver = CreateFinishedClientDriver();
        if (!tempDriver.TryInstallOneRttKeyUpdate())
        {
            throw new InvalidOperationException("Failed to prepare the representative successor 1-RTT install state.");
        }

        installedOpenPacketProtectionMaterial = tempDriver.State.OneRttOpenPacketProtectionMaterial
            ?? throw new InvalidOperationException("The representative successor 1-RTT open material was not available.");
        installedProtectPacketProtectionMaterial = tempDriver.State.OneRttProtectPacketProtectionMaterial
            ?? throw new InvalidOperationException("The representative successor 1-RTT protect material was not available.");

        packetCoordinator = new QuicHandshakeFlowCoordinator(DestinationConnectionId);
        if (!packetCoordinator.TrySetDestinationConnectionId(DestinationConnectionId))
        {
            throw new InvalidOperationException("Failed to configure the packet coordinator destination connection ID.");
        }

        if (!packetCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            installedProtectPacketProtectionMaterial,
            keyPhase: true,
            out protectedPacket))
        {
            throw new InvalidOperationException("Failed to prepare representative successor 1-RTT protected packet.");
        }
    }

    /// <summary>
    /// Rebuilds the deterministic client-handshake state to the boundary immediately before successor key-update installation.
    /// </summary>
    [IterationSetup]
    public void IterationSetup()
    {
        installDriver = CreateFinishedClientDriver();
    }

    /// <summary>
    /// Measures the successor 1-RTT key-update install boundary that retains the current application traffic secrets long enough to derive the next packet-protection pair.
    /// </summary>
    [Benchmark]
    public int InstallSuccessorOneRttPacketProtectionMaterial()
    {
        return installDriver.TryInstallOneRttKeyUpdate() ? 1 : -1;
    }

    /// <summary>
    /// Measures 1-RTT short-header packet formatting with an explicit Key Phase bit after successor installation.
    /// </summary>
    [Benchmark]
    public int BuildProtectedApplicationPacketWithInstalledKeyPhaseBit()
    {
        QuicHandshakeFlowCoordinator coordinator = new(DestinationConnectionId);
        if (!coordinator.TrySetDestinationConnectionId(DestinationConnectionId)
            || !coordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                installedProtectPacketProtectionMaterial,
                keyPhase: true,
                out byte[] packet))
        {
            return -1;
        }

        return packet.Length;
    }

    /// <summary>
    /// Measures 1-RTT short-header packet opening while surfacing the observed Key Phase bit after successor installation.
    /// </summary>
    [Benchmark]
    public int OpenProtectedApplicationPacketAndReadKeyPhaseBit()
    {
        return packetCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            installedOpenPacketProtectionMaterial,
            out byte[] openedPacket,
            out _,
            out _,
            out bool keyPhase)
            ? openedPacket.Length + (keyPhase ? 1 : 0)
            : -1;
    }

    private QuicTlsTransportBridgeDriver CreateFinishedClientDriver()
    {
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        leafKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
        if (bootstrapUpdates.Count != 2)
        {
            throw new InvalidOperationException("Failed to prepare the representative client handshake bootstrap.");
        }

        (
            byte[] serverHello,
            byte[] encryptedExtensions,
            byte[] certificate,
            byte[] certificateVerify,
            byte[] finished) = PrepareClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localHandshakePrivateKey,
            peerTransportParameters,
            leafKey,
            leafCertificateDer);

        if (driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, serverHello).Count != 4
            || driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, encryptedExtensions).Count != 1
            || driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, certificate).Count != 1
            || driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, certificateVerify).Count != 3
            || driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, finished).Count != 8)
        {
            throw new InvalidOperationException("Failed to prepare the representative client Finished publication boundary.");
        }

        if (!driver.State.OneRttKeysAvailable || !driver.State.PeerHandshakeTranscriptCompleted)
        {
            throw new InvalidOperationException("The representative client Finished boundary did not reach active 1-RTT state.");
        }

        return driver;
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
        byte[] certificateVerify = CreateCertificateVerifyTranscript(leafKey, certificateVerifyTranscriptHash);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = schedule.ProcessTranscriptStep(CreateServerHelloStep(serverHello));
        if (serverHelloUpdates.Count != 3)
        {
            throw new InvalidOperationException("Failed to prepare the representative serverHello transcript.");
        }

        if (!schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] serverHelloOnlyVerifyData))
        {
            throw new InvalidOperationException("Failed to prepare the representative Finished transcript.");
        }

        if (schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)).Count != 0
            || schedule.ProcessTranscriptStep(CreateCertificateStep(leafCertificateDer)).Count != 0
            || schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(certificateVerify)).Count != 1)
        {
            throw new InvalidOperationException("Failed to prepare the representative certificate flight.");
        }

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
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }
}
