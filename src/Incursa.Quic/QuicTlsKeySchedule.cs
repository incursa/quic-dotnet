using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Incursa.Quic;

/// <summary>
/// Owns the narrow managed TLS 1.3 key schedule slice for the current endpoint role.
/// </summary>
internal sealed class QuicTlsKeySchedule
{
    private const int HandshakeHeaderLength = 4;
    private const int HkdfLengthFieldLength = sizeof(ushort);
    private const int HkdfLabelLengthFieldLength = 1;
    private const int HkdfContextLengthFieldLength = 1;
    private const int HkdfExpandCounterLength = 1;
    private const byte HkdfExpandCounterValue = 1;
    private const int HashLength = 32;
    private const int Secp256r1CoordinateLength = 32;
    private const int UncompressedPointLength = 1 + (Secp256r1CoordinateLength * 2);
    private const byte UncompressedPointFormat = 0x04;
    private const ushort HandshakeTranscriptVerificationFailureAlertDescription = 0x0033;
    private const ushort HandshakeTranscriptParseFailureAlertDescription = 0x0032;
    private const int UInt16Length = sizeof(ushort);
    private const int UInt24Length = 3;
    private const int UInt24HighByteShift = 16;
    private const int UInt24MidByteShift = 8;
    private const int UInt24HighByteIndex = 0;
    private const int UInt24MidByteIndex = 1;
    private const int UInt24LowByteIndex = 2;
    private const int TlsRandomLength = 32;
    private const byte NullCompressionMethod = 0x00;
    private const int MaximumSessionIdLength = 32;
    private const ushort TlsLegacyVersion = 0x0303;
    private const ushort Tls13Version = 0x0304;
    private const ushort SupportedVersionsExtensionType = 0x002b;
    private const ushort KeyShareExtensionType = 0x0033;
    private const ushort Secp256r1NamedGroup = (ushort)QuicTlsNamedGroup.Secp256r1;
    private const int CertificateVerifyContextPrefixLength = 64;
    private const int EcdsaP256KeySizeBits = 256;
    private const byte CertificateVerifySignedDataPrefixByte = 0x20;
    private const DSASignatureFormat CertificateVerifySignatureFormat = DSASignatureFormat.Rfc3279DerSequence;

    private static readonly byte[] HkdfLabelPrefix = Encoding.ASCII.GetBytes("tls13 ");
    private static readonly byte[] DerivedLabel = Encoding.ASCII.GetBytes("derived");
    private static readonly byte[] ClientHandshakeTrafficLabel = Encoding.ASCII.GetBytes("c hs traffic");
    private static readonly byte[] ServerHandshakeTrafficLabel = Encoding.ASCII.GetBytes("s hs traffic");
    private static readonly byte[] FinishedLabel = Encoding.ASCII.GetBytes("finished");
    private static readonly byte[] ServerCertificateVerifyContext = Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify");
    private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicHpLabel = Encoding.ASCII.GetBytes("quic hp");
    private static readonly byte[] EmptyTranscriptHash = SHA256.HashData(Array.Empty<byte>());
    private static readonly QuicAeadUsageLimits HandshakeUsageLimits = new(64, 128);

    private readonly QuicTlsRole role;
    private readonly ECDiffieHellman localKeyPair;
    private readonly QuicTlsCipherSuiteProfile profile;
    private readonly ArrayBufferWriter<byte> transcriptBytes = new();
    private readonly byte[] localKeyShare;

    private byte[]? serverHandshakeTrafficSecret;
    private byte[]? peerLeafCertificateDer;
    private bool handshakeSecretsDerived;
    private bool peerCertificateVerifyVerified;
    private bool peerFinishedVerified;
    private bool isTerminal;

    /// <summary>
    /// Creates the client-role TLS key schedule, optionally seeded with a deterministic local private key for tests.
    /// </summary>
    /// <param name="localPrivateKey">An optional P-256 private scalar to import for deterministic tests.</param>
    internal QuicTlsKeySchedule(ReadOnlyMemory<byte> localPrivateKey = default)
        : this(QuicTlsRole.Client, localPrivateKey)
    {
    }

    /// <summary>
    /// Creates the managed TLS key schedule for the current role, optionally seeded with a deterministic local private key for tests.
    /// </summary>
    /// <param name="role">The endpoint role that owns the key schedule.</param>
    /// <param name="localPrivateKey">An optional P-256 private scalar to import for deterministic tests.</param>
    internal QuicTlsKeySchedule(QuicTlsRole role, ReadOnlyMemory<byte> localPrivateKey = default)
    {
        this.role = role;

        if (!QuicTlsCipherSuiteProfile.TryGet(QuicTlsCipherSuite.TlsAes128GcmSha256, out profile))
        {
            throw new InvalidOperationException("The supported TLS 1.3 profile is unavailable.");
        }

        localKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        if (!localPrivateKey.IsEmpty)
        {
            try
            {
                localKeyPair.ImportParameters(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = localPrivateKey.ToArray(),
                });
            }
            catch (CryptographicException ex)
            {
                throw new ArgumentException("The local private key must be a valid P-256 scalar.", nameof(localPrivateKey), ex);
            }
        }

        localKeyShare = ExportUncompressedPoint(localKeyPair.ExportParameters(true));
    }

    /// <summary>
    /// Gets the public local ephemeral key share associated with the current role's key pair.
    /// </summary>
    public ReadOnlyMemory<byte> LocalKeyShare => localKeyShare;

    /// <summary>
    /// Gets whether the key schedule has already published handshake traffic secrets.
    /// </summary>
    public bool HandshakeSecretsDerived => handshakeSecretsDerived;

    /// <summary>
    /// Gets whether the peer Finished has been verified with the managed key schedule.
    /// </summary>
    public bool PeerFinishedVerified => peerFinishedVerified;

    /// <summary>
    /// Gets whether the peer CertificateVerify signature has been verified with the managed key schedule.
    /// </summary>
    public bool PeerCertificateVerifyVerified => peerCertificateVerifyVerified;

    /// <summary>
    /// Gets the peer Finished verify data for the current handshake transcript, if the handshake secret has been derived.
    /// </summary>
    internal bool TryGetExpectedPeerFinishedVerifyData(out byte[] verifyData)
    {
        verifyData = Array.Empty<byte>();

        if (role != QuicTlsRole.Client || serverHandshakeTrafficSecret is null)
        {
            return false;
        }

        verifyData = DeriveFinishedVerifyData(serverHandshakeTrafficSecret, HashTranscript());
        return true;
    }

    /// <summary>
    /// Gets the SHA-256 fingerprint of the parsed peer leaf certificate, if one has already been staged.
    /// </summary>
    internal bool TryGetPeerLeafCertificateSha256Fingerprint(out byte[] fingerprint)
    {
        fingerprint = Array.Empty<byte>();

        if (peerLeafCertificateDer is null)
        {
            return false;
        }

        fingerprint = SHA256.HashData(peerLeafCertificateDer);
        return true;
    }

    /// <summary>
    /// Processes one handshake transcript step and returns any bridge-visible updates produced by the key schedule.
    /// </summary>
    internal IReadOnlyList<QuicTlsStateUpdate> ProcessTranscriptStep(QuicTlsTranscriptStep step)
    {
        if (isTerminal || step.HandshakeMessageType is null || step.HandshakeMessageBytes.IsEmpty)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (role == QuicTlsRole.Server)
        {
            return step.HandshakeMessageType.Value switch
            {
                QuicTlsHandshakeMessageType.ClientHello => ProcessClientHello(step),
                _ => BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription),
            };
        }

        return step.HandshakeMessageType.Value switch
        {
            QuicTlsHandshakeMessageType.ServerHello => ProcessServerHello(step),
            QuicTlsHandshakeMessageType.EncryptedExtensions => AppendTranscriptMessage(step.HandshakeMessageBytes.Span),
            QuicTlsHandshakeMessageType.Certificate => ProcessCertificate(step),
            QuicTlsHandshakeMessageType.CertificateVerify => ProcessCertificateVerify(step),
            QuicTlsHandshakeMessageType.Finished => ProcessFinished(step),
            _ => AppendTranscriptMessage(step.HandshakeMessageBytes.Span),
        };
    }

    private IReadOnlyList<QuicTlsStateUpdate> ProcessClientHello(QuicTlsTranscriptStep step)
    {
        if (handshakeSecretsDerived
            || step.Kind != QuicTlsTranscriptStepKind.PeerTransportParametersStaged
            || step.TranscriptPhase != QuicTlsTranscriptPhase.Completed
            || step.HandshakeMessageType != QuicTlsHandshakeMessageType.ClientHello
            || step.HandshakeMessageLength is null
            || step.TransportParameters is null
            || step.SelectedCipherSuite != profile.CipherSuite
            || step.TranscriptHashAlgorithm != profile.TranscriptHashAlgorithm
            || step.NamedGroup != profile.NamedGroup
            || step.KeyShare.IsEmpty)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        AppendTranscriptMessage(step.HandshakeMessageBytes.Span);
        if (!TryCreateServerHello(step.HandshakeMessageBytes.Span, out byte[] serverHelloBytes))
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        AppendTranscriptMessage(serverHelloBytes);
        ReadOnlySpan<byte> transcriptHash = HashTranscript();
        if (!TryDeriveHandshakeTrafficSecrets(
                step.KeyShare.Span,
                transcriptHash,
                protectWithClientTrafficSecret: false,
                out QuicTlsPacketProtectionMaterial openMaterial,
                out QuicTlsPacketProtectionMaterial protectMaterial))
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        handshakeSecretsDerived = true;
        return
        [
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.CryptoDataAvailable,
                QuicTlsEncryptionLevel.Handshake,
                CryptoDataOffset: 0,
                CryptoData: serverHelloBytes),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: openMaterial),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: protectMaterial),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.KeysAvailable,
                QuicTlsEncryptionLevel.Handshake),
        ];
    }

    private IReadOnlyList<QuicTlsStateUpdate> ProcessServerHello(QuicTlsTranscriptStep step)
    {
        if (handshakeSecretsDerived)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (step.SelectedCipherSuite != profile.CipherSuite
            || step.TranscriptHashAlgorithm != profile.TranscriptHashAlgorithm
            || step.NamedGroup != profile.NamedGroup
            || step.KeyShare.IsEmpty)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        AppendTranscriptMessage(step.HandshakeMessageBytes.Span);
        ReadOnlySpan<byte> transcriptHash = HashTranscript();

        if (!TryDeriveHandshakeTrafficSecrets(
                step.KeyShare.Span,
                transcriptHash,
                protectWithClientTrafficSecret: true,
                out QuicTlsPacketProtectionMaterial openMaterial,
                out QuicTlsPacketProtectionMaterial protectMaterial))
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        handshakeSecretsDerived = true;
        return
        [
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: openMaterial),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: protectMaterial),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.KeysAvailable,
                QuicTlsEncryptionLevel.Handshake),
        ];
    }

    private IReadOnlyList<QuicTlsStateUpdate> ProcessCertificate(QuicTlsTranscriptStep step)
    {
        if (peerLeafCertificateDer is not null)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        if (!TryParsePeerLeafCertificate(step.HandshakeMessageBytes.Span, out byte[] leafCertificateDer))
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        peerLeafCertificateDer = leafCertificateDer;
        AppendTranscriptMessage(step.HandshakeMessageBytes.Span);
        return Array.Empty<QuicTlsStateUpdate>();
    }

    private IReadOnlyList<QuicTlsStateUpdate> ProcessCertificateVerify(QuicTlsTranscriptStep step)
    {
        if (peerLeafCertificateDer is null || peerCertificateVerifyVerified)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        if (!TryParseCertificateVerify(
            step.HandshakeMessageBytes.Span,
            out QuicTlsSignatureScheme signatureScheme,
            out byte[] signature))
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        if (!TryVerifyCertificateVerifySignature(signatureScheme, signature))
        {
            return BuildFatalAlert(HandshakeTranscriptVerificationFailureAlertDescription);
        }

        AppendTranscriptMessage(step.HandshakeMessageBytes.Span);
        peerCertificateVerifyVerified = true;
        return [new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerCertificateVerifyVerified)];
    }

    private IReadOnlyList<QuicTlsStateUpdate> ProcessFinished(QuicTlsTranscriptStep step)
    {
        if (!handshakeSecretsDerived
            || serverHandshakeTrafficSecret is null
            || step.HandshakeMessageBytes.Length != HandshakeHeaderLength + HashLength)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        ReadOnlySpan<byte> expectedFinished = step.HandshakeMessageBytes.Span.Slice(HandshakeHeaderLength, HashLength);
        ReadOnlySpan<byte> transcriptHash = HashTranscript();
        byte[] expectedVerifyData = DeriveFinishedVerifyData(serverHandshakeTrafficSecret, transcriptHash);
        if (!expectedFinished.SequenceEqual(expectedVerifyData))
        {
            return BuildFatalAlert(HandshakeTranscriptVerificationFailureAlertDescription);
        }

        AppendTranscriptMessage(step.HandshakeMessageBytes.Span);
        peerFinishedVerified = true;
        return [new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified)];
    }

    private bool TryDeriveHandshakeTrafficSecrets(
        ReadOnlySpan<byte> peerKeyShareBytes,
        ReadOnlySpan<byte> transcriptHash,
        bool protectWithClientTrafficSecret,
        out QuicTlsPacketProtectionMaterial openMaterial,
        out QuicTlsPacketProtectionMaterial protectMaterial)
    {
        openMaterial = default;
        protectMaterial = default;

        if (peerKeyShareBytes.Length != UncompressedPointLength || peerKeyShareBytes[0] != UncompressedPointFormat)
        {
            return false;
        }

        byte[] sharedSecret;
        try
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            peer.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = peerKeyShareBytes.Slice(1, Secp256r1CoordinateLength).ToArray(),
                    Y = peerKeyShareBytes.Slice(1 + Secp256r1CoordinateLength, Secp256r1CoordinateLength).ToArray(),
                },
            });

            sharedSecret = localKeyPair.DeriveKeyMaterial(peer.PublicKey);
        }
        catch (CryptographicException)
        {
            return false;
        }

        byte[] earlySecret = HkdfExtract(new byte[HashLength], []);
        byte[] derivedSecret = HkdfExpandLabel(earlySecret, DerivedLabel, EmptyTranscriptHash, HashLength);
        byte[] handshakeSecret = HkdfExtract(derivedSecret, sharedSecret);
        byte[] clientHandshakeTrafficSecret = HkdfExpandLabel(handshakeSecret, ClientHandshakeTrafficLabel, transcriptHash, HashLength);
        serverHandshakeTrafficSecret = HkdfExpandLabel(handshakeSecret, ServerHandshakeTrafficLabel, transcriptHash, HashLength);

        ReadOnlySpan<byte> openTrafficSecret = protectWithClientTrafficSecret
            ? serverHandshakeTrafficSecret
            : clientHandshakeTrafficSecret;
        ReadOnlySpan<byte> protectTrafficSecret = protectWithClientTrafficSecret
            ? clientHandshakeTrafficSecret
            : serverHandshakeTrafficSecret;

        if (!TryCreateHandshakePacketProtectionMaterial(openTrafficSecret, out openMaterial)
            || !TryCreateHandshakePacketProtectionMaterial(protectTrafficSecret, out protectMaterial))
        {
            return false;
        }

        return true;
    }

    private static bool TryCreateHandshakePacketProtectionMaterial(
        ReadOnlySpan<byte> trafficSecret,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        byte[] aeadKey = HkdfExpandLabel(trafficSecret, QuicKeyLabel, [], 16);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, QuicIvLabel, [], 12);
        byte[] headerProtectionKey = HkdfExpandLabel(trafficSecret, QuicHpLabel, [], 16);

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            HandshakeUsageLimits,
            out material);
    }

    private bool TryCreateServerHello(ReadOnlySpan<byte> clientHelloBytes, out byte[] serverHelloBytes)
    {
        serverHelloBytes = Array.Empty<byte>();

        if (!TryParseClientHelloSessionId(clientHelloBytes, out byte[] sessionId))
        {
            return false;
        }

        byte[] serverRandom = SHA256.HashData([.. localKeyShare, .. clientHelloBytes]);
        int sessionIdLength = sessionId.Length;
        int keyShareExtensionLength = UInt16Length + UInt16Length + localKeyShare.Length;
        int extensionsLength =
            (UInt16Length + UInt16Length + UInt16Length)
            + (UInt16Length + UInt16Length + keyShareExtensionLength);
        byte[] body = new byte[
            UInt16Length
            + TlsRandomLength
            + 1
            + sessionIdLength
            + UInt16Length
            + 1
            + UInt16Length
            + extensionsLength];

        int index = 0;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), TlsLegacyVersion);
        index += UInt16Length;
        serverRandom.CopyTo(body, index);
        index += TlsRandomLength;

        body[index++] = checked((byte)sessionIdLength);
        if (sessionIdLength > 0)
        {
            sessionId.CopyTo(body, index);
            index += sessionIdLength;
        }

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), (ushort)profile.CipherSuite);
        index += UInt16Length;
        body[index++] = NullCompressionMethod;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)extensionsLength));
        index += UInt16Length;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SupportedVersionsExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), UInt16Length);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), Tls13Version);
        index += UInt16Length;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), KeyShareExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)keyShareExtensionLength));
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), Secp256r1NamedGroup);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)localKeyShare.Length));
        index += UInt16Length;
        localKeyShare.CopyTo(body, index);

        serverHelloBytes = WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
        return true;
    }

    private static bool TryParseClientHelloSessionId(ReadOnlySpan<byte> clientHelloBytes, out byte[] sessionId)
    {
        sessionId = Array.Empty<byte>();

        if (clientHelloBytes.Length <= HandshakeHeaderLength
            || clientHelloBytes[0] != (byte)QuicTlsHandshakeMessageType.ClientHello)
        {
            return false;
        }

        ReadOnlySpan<byte> clientHelloBody = clientHelloBytes.Slice(HandshakeHeaderLength);
        int index = 0;
        if (!TryReadUInt16(clientHelloBody, ref index, out ushort legacyVersion)
            || legacyVersion != TlsLegacyVersion
            || !TrySkipBytes(clientHelloBody, ref index, TlsRandomLength)
            || !TryReadUInt8(clientHelloBody, ref index, out int sessionIdLength)
            || sessionIdLength > MaximumSessionIdLength
            || !TrySkipBytes(clientHelloBody, ref index, sessionIdLength))
        {
            return false;
        }

        sessionId = clientHelloBody.Slice(index - sessionIdLength, sessionIdLength).ToArray();
        return true;
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[HandshakeHeaderLength + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, UInt24Length), body.Length);
        body.CopyTo(transcript.AsSpan(HandshakeHeaderLength));
        return transcript;
    }

    private bool TryParsePeerLeafCertificate(
        ReadOnlySpan<byte> handshakeMessageBytes,
        out byte[] leafCertificateDer)
    {
        leafCertificateDer = Array.Empty<byte>();

        if (handshakeMessageBytes.Length <= HandshakeHeaderLength)
        {
            return false;
        }

        ReadOnlySpan<byte> handshakeMessageBody = handshakeMessageBytes.Slice(HandshakeHeaderLength);
        int index = 0;
        if (!TryReadUInt8(handshakeMessageBody, ref index, out int certificateRequestContextLength)
            || certificateRequestContextLength != 0
            || !TrySkipBytes(handshakeMessageBody, ref index, certificateRequestContextLength)
            || !TryReadUInt24(handshakeMessageBody, ref index, out uint certificateListLength)
            || certificateListLength == 0
            || !TrySkipBytes(handshakeMessageBody, ref index, checked((int)certificateListLength))
            || index != handshakeMessageBody.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> certificateList = handshakeMessageBody.Slice(
            handshakeMessageBody.Length - checked((int)certificateListLength),
            checked((int)certificateListLength));

        int certificateListIndex = 0;
        if (!TryReadUInt24(certificateList, ref certificateListIndex, out uint certificateLength)
            || certificateLength == 0
            || certificateLength > int.MaxValue
            || certificateList.Length - certificateListIndex < checked((int)certificateLength) + UInt16Length
            || !TrySkipBytes(certificateList, ref certificateListIndex, checked((int)certificateLength))
            || !TryReadUInt16(certificateList, ref certificateListIndex, out ushort certificateExtensionsLength)
            || certificateExtensionsLength != 0
            || !TrySkipBytes(certificateList, ref certificateListIndex, certificateExtensionsLength)
            || certificateListIndex != certificateList.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> leafCertificateBytes = certificateList.Slice(
            certificateListIndex - UInt16Length - checked((int)certificateLength),
            checked((int)certificateLength));

        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(leafCertificateBytes.ToArray());
            using ECDsa? publicKey = certificate.GetECDsaPublicKey();
            if (publicKey is null || !TryValidateEcdsaP256PublicKey(publicKey))
            {
                return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }

        leafCertificateDer = leafCertificateBytes.ToArray();
        return true;
    }

    private static bool TryParseCertificateVerify(
        ReadOnlySpan<byte> handshakeMessageBytes,
        out QuicTlsSignatureScheme signatureScheme,
        out byte[] signature)
    {
        signatureScheme = default;
        signature = Array.Empty<byte>();

        if (handshakeMessageBytes.Length <= HandshakeHeaderLength + UInt16Length + UInt16Length)
        {
            return false;
        }

        ReadOnlySpan<byte> handshakeMessageBody = handshakeMessageBytes.Slice(HandshakeHeaderLength);
        int index = 0;
        if (!TryReadUInt16(handshakeMessageBody, ref index, out ushort signatureSchemeValue)
            || !TryMapSignatureScheme(signatureSchemeValue, out signatureScheme)
            || !TryReadUInt16(handshakeMessageBody, ref index, out ushort signatureLength)
            || signatureLength == 0
            || !TrySkipBytes(handshakeMessageBody, ref index, signatureLength)
            || index != handshakeMessageBody.Length)
        {
            return false;
        }

        signature = handshakeMessageBody.Slice(
            handshakeMessageBody.Length - signatureLength,
            signatureLength).ToArray();
        return true;
    }

    private bool TryVerifyCertificateVerifySignature(
        QuicTlsSignatureScheme signatureScheme,
        ReadOnlySpan<byte> signature)
    {
        if (signatureScheme != QuicTlsSignatureScheme.EcdsaSecp256r1Sha256
            || peerLeafCertificateDer is null)
        {
            return false;
        }

        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(peerLeafCertificateDer);
            using ECDsa? publicKey = certificate.GetECDsaPublicKey();
            if (publicKey is null || !TryValidateEcdsaP256PublicKey(publicKey))
            {
                return false;
            }

            byte[] transcriptHash = HashTranscript();
            Span<byte> signedData = stackalloc byte[CertificateVerifyContextPrefixLength
                + ServerCertificateVerifyContext.Length
                + 1
                + HashLength];
            signedData[..CertificateVerifyContextPrefixLength].Fill(CertificateVerifySignedDataPrefixByte);
            ServerCertificateVerifyContext.CopyTo(signedData.Slice(CertificateVerifyContextPrefixLength));
            signedData[CertificateVerifyContextPrefixLength + ServerCertificateVerifyContext.Length] = 0x00;
            transcriptHash.AsSpan().CopyTo(
                signedData.Slice(CertificateVerifyContextPrefixLength + ServerCertificateVerifyContext.Length + 1));

            return publicKey.VerifyData(
                signedData,
                signature,
                HashAlgorithmName.SHA256,
                CertificateVerifySignatureFormat);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryValidateEcdsaP256PublicKey(ECDsa publicKey)
    {
        if (publicKey.KeySize != EcdsaP256KeySizeBits)
        {
            return false;
        }

        try
        {
            ECParameters parameters = publicKey.ExportParameters(false);
            return parameters.Curve.IsNamed
                && parameters.Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryMapSignatureScheme(
        ushort signatureSchemeValue,
        out QuicTlsSignatureScheme signatureScheme)
    {
        signatureScheme = (QuicTlsSignatureScheme)signatureSchemeValue;
        return signatureScheme == QuicTlsSignatureScheme.EcdsaSecp256r1Sha256;
    }

    private IReadOnlyList<QuicTlsStateUpdate> AppendTranscriptMessage(ReadOnlySpan<byte> handshakeMessageBytes)
    {
        if (handshakeMessageBytes.IsEmpty)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        Span<byte> destination = transcriptBytes.GetSpan(handshakeMessageBytes.Length);
        handshakeMessageBytes.CopyTo(destination);
        transcriptBytes.Advance(handshakeMessageBytes.Length);
        return Array.Empty<QuicTlsStateUpdate>();
    }

    private byte[] HashTranscript()
    {
        return SHA256.HashData(transcriptBytes.WrittenSpan);
    }

    private static byte[] DeriveFinishedVerifyData(ReadOnlySpan<byte> trafficSecret, ReadOnlySpan<byte> transcriptHash)
    {
        byte[] finishedKey = HkdfExpandLabel(trafficSecret, FinishedLabel, [], HashLength);
        using HMACSHA256 hmac = new(finishedKey);
        return hmac.ComputeHash(transcriptHash.ToArray());
    }

    private static byte[] HkdfExtract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
    {
        using HMACSHA256 hmac = new(salt.ToArray());
        return hmac.ComputeHash(inputKeyMaterial.ToArray());
    }

    private static byte[] HkdfExpandLabel(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int length)
    {
        int hkdfLabelLength = HkdfLengthFieldLength
            + HkdfLabelLengthFieldLength
            + HkdfLabelPrefix.Length
            + label.Length
            + HkdfContextLengthFieldLength
            + context.Length;

        Span<byte> hkdfLabel = stackalloc byte[hkdfLabelLength];
        int index = 0;

        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel, checked((ushort)length));
        index += HkdfLengthFieldLength;

        hkdfLabel[index++] = checked((byte)(HkdfLabelPrefix.Length + label.Length));
        HkdfLabelPrefix.CopyTo(hkdfLabel[index..]);
        index += HkdfLabelPrefix.Length;

        label.CopyTo(hkdfLabel[index..]);
        index += label.Length;

        hkdfLabel[index++] = checked((byte)context.Length);
        if (!context.IsEmpty)
        {
            context.CopyTo(hkdfLabel[index..]);
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

    private IReadOnlyList<QuicTlsStateUpdate> BuildFatalAlert(ushort alertDescription)
    {
        isTerminal = true;
        peerLeafCertificateDer = null;
        peerCertificateVerifyVerified = false;
        return [new QuicTlsStateUpdate(QuicTlsUpdateKind.FatalAlert, AlertDescription: alertDescription)];
    }

    private static bool TryReadUInt8(ReadOnlySpan<byte> source, ref int index, out int value)
    {
        if ((uint)index >= (uint)source.Length)
        {
            value = default;
            return false;
        }

        value = source[index++];
        return true;
    }

    private static bool TryReadUInt16(ReadOnlySpan<byte> source, ref int index, out ushort value)
    {
        if (index > source.Length - UInt16Length)
        {
            value = default;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(index, UInt16Length));
        index += UInt16Length;
        return true;
    }

    private static bool TryReadUInt24(ReadOnlySpan<byte> source, ref int index, out uint value)
    {
        if (index > source.Length - UInt24Length)
        {
            value = default;
            return false;
        }

        value = ReadUInt24(source.Slice(index, UInt24Length));
        index += UInt24Length;
        return true;
    }

    private static bool TrySkipBytes(ReadOnlySpan<byte> source, ref int index, int length)
    {
        if (length < 0 || index > source.Length - length)
        {
            return false;
        }

        index += length;
        return true;
    }

    private static uint ReadUInt24(ReadOnlySpan<byte> source)
    {
        return (uint)((source[UInt24HighByteIndex] << UInt24HighByteShift)
            | (source[UInt24MidByteIndex] << UInt24MidByteShift)
            | source[UInt24LowByteIndex]);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[UInt24HighByteIndex] = (byte)(value >> UInt24HighByteShift);
        destination[UInt24MidByteIndex] = (byte)(value >> UInt24MidByteShift);
        destination[UInt24LowByteIndex] = (byte)value;
    }

    private static byte[] ExportUncompressedPoint(ECParameters parameters)
    {
        if (parameters.Q.X is null || parameters.Q.Y is null)
        {
            throw new InvalidOperationException("The local key pair does not have an exportable public point.");
        }

        byte[] keyShare = new byte[UncompressedPointLength];
        keyShare[0] = UncompressedPointFormat;
        parameters.Q.X.CopyTo(keyShare, 1);
        parameters.Q.Y.CopyTo(keyShare, 1 + Secp256r1CoordinateLength);
        return keyShare;
    }
}
