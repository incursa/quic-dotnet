using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Security;
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
    private const ushort NoApplicationProtocolAlertDescription = 0x0078;
    private const int UInt16Length = sizeof(ushort);
    private const int UInt24Length = 3;
    private const int CertificateRequestContextLength = 0;
    private const ushort CertificateRequestExtensionsLength = 8;
    private const ushort CertificateRequestSignatureAlgorithmsExtensionType = 0x000D;
    private const ushort CertificateRequestSignatureAlgorithmsExtensionLength = 4;
    private const ushort CertificateRequestSignatureSchemeListLength = 2;
    private const int UInt24HighByteShift = 16;
    private const int UInt24MidByteShift = 8;
    private const int UInt24HighByteIndex = 0;
    private const int UInt24MidByteIndex = 1;
    private const int UInt24LowByteIndex = 2;
    private const int HeaderProtectionKeyLength = 16;
    private const int TlsRandomLength = 32;
    private const byte NullCompressionMethod = 0x00;
    private const int MaximumSessionIdLength = 32;
    private const ushort TlsLegacyVersion = 0x0303;
    private const ushort Tls13Version = 0x0304;
    private const ushort ApplicationLayerProtocolNegotiationExtensionType = 0x0010;
    private const ushort SignatureAlgorithmsExtensionType = 0x000d;
    private const ushort SupportedGroupsExtensionType = 0x000a;
    private const ushort SupportedVersionsExtensionType = 0x002b;
    private const ushort KeyShareExtensionType = 0x0033;
    private const ushort PreSharedKeyExtensionType = 0x0029;
    private const ushort PskKeyExchangeModesExtensionType = 0x002d;
    private const ushort Secp256r1NamedGroup = (ushort)QuicTlsNamedGroup.Secp256r1;
    private const ushort TlsCipherSuitesListLength = UInt16Length;
    private const ushort SignatureAlgorithmsVectorLength = UInt16Length;
    private const ushort SupportedGroupsVectorLength = UInt16Length;
    private const byte SupportedVersionsVectorLength = (byte)UInt16Length;
    private const ushort SignatureAlgorithmsExtensionBodyLength = UInt16Length + UInt16Length;
    private const ushort SupportedGroupsExtensionBodyLength = UInt16Length + UInt16Length;
    private const ushort SupportedVersionsExtensionBodyLength = 1 + UInt16Length;
    private const ushort KeyShareEntryFixedLength = UInt16Length + UInt16Length;
    private const byte PskKeyExchangeModesVectorLength = 1;
    private const byte PskDheKeMode = 0x01;
    private const int CertificateVerifyContextPrefixLength = 64;
    private const int EcdsaP256KeySizeBits = 256;
    private const byte CertificateVerifySignedDataPrefixByte = 0x20;
    private const DSASignatureFormat CertificateVerifySignatureFormat = DSASignatureFormat.Rfc3279DerSequence;
    private const byte MessageHashHandshakeType = 0xFE;

    private static readonly byte[] HkdfLabelPrefix = Encoding.ASCII.GetBytes("tls13 ");
    private static readonly byte[] DerivedLabel = Encoding.ASCII.GetBytes("derived");
    private static readonly byte[] ClientHandshakeTrafficLabel = Encoding.ASCII.GetBytes("c hs traffic");
    private static readonly byte[] ServerHandshakeTrafficLabel = Encoding.ASCII.GetBytes("s hs traffic");
    private static readonly byte[] ClientEarlyTrafficLabel = Encoding.ASCII.GetBytes("c e traffic");
    private static readonly byte[] ClientApplicationTrafficLabel = Encoding.ASCII.GetBytes("c ap traffic");
    private static readonly byte[] ServerApplicationTrafficLabel = Encoding.ASCII.GetBytes("s ap traffic");
    private static readonly byte[] QuicKeyUpdateLabel = Encoding.ASCII.GetBytes("quic ku");
    private static readonly byte[] FinishedLabel = Encoding.ASCII.GetBytes("finished");
    private static readonly byte[] ResumptionMasterLabel = Encoding.ASCII.GetBytes("res master");
    private static readonly byte[] ResumptionLabel = Encoding.ASCII.GetBytes("resumption");
    private static readonly byte[] ResumptionBinderLabel = Encoding.ASCII.GetBytes("res binder");
    private static readonly byte[] DeterministicClientHelloRandomLabel = Encoding.ASCII.GetBytes("incursa.quic.client-random");
    private static readonly byte[] ServerCertificateVerifyContext = Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify");
    private static readonly byte[] ClientCertificateVerifyContext = Encoding.ASCII.GetBytes("TLS 1.3, client CertificateVerify");
    private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicHpLabel = Encoding.ASCII.GetBytes("quic hp");
    private static readonly byte[] HelloRetryRequestRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
    private static readonly byte[] ZeroHashInput = new byte[HashLength];
    private static readonly byte[] EmptyTranscriptHash = SHA256.HashData(Array.Empty<byte>());
    /// <summary>
    /// Gets the RFC 9001 Appendix B usage limits used for supported packet-protection materials.
    /// </summary>
    private static readonly QuicAeadUsageLimits PacketProtectionUsageLimits = CreatePacketProtectionUsageLimits();

    private readonly QuicTlsRole role;
    private readonly ECDiffieHellman localKeyPair;
    private readonly QuicTlsCipherSuiteProfile profile;
    private readonly ArrayBufferWriter<byte> transcriptBytes = new();
    private readonly byte[] localKeyShare;
    private readonly byte[]? deterministicClientHelloRandom;
    private byte[][] applicationProtocols;
    private byte[]? localHandshakeTranscriptPrefix;

    private byte[]? handshakeSecret;
    private byte[]? clientHandshakeTrafficSecret;
    private byte[]? serverHandshakeTrafficSecret;
    private byte[]? resumptionMasterSecret;
    private byte[]? clientApplicationTrafficSecret;
    private byte[]? serverApplicationTrafficSecret;
    private byte[]? peerLeafCertificateDer;
    private bool handshakeSecretsDerived;
    private bool localServerFlightCompleted;
    private bool serverClientCertificateRequired;
    private bool peerCertificateVerifyVerified;
    private bool peerFinishedVerified;
    private bool resumptionAttemptPending;
    private bool serverHelloRetryRequestPending;
    private bool isTerminal;
    private ulong nextServerInitialCryptoOffset;

    /// <summary>
    /// Creates the client-role TLS key schedule, optionally seeded with a deterministic local private key for tests.
    /// </summary>
    /// <param name="localPrivateKey">An optional P-256 private scalar to import for deterministic tests.</param>
    /// <param name="applicationProtocols">The configured ALPN protocols to advertise for the client role.</param>
    internal QuicTlsKeySchedule(
        ReadOnlyMemory<byte> localPrivateKey = default,
        IReadOnlyList<SslApplicationProtocol>? applicationProtocols = null)
        : this(QuicTlsRole.Client, localPrivateKey, applicationProtocols)
    {
    }

    /// <summary>
    /// Creates the managed TLS key schedule for the current role, optionally seeded with a deterministic local private key for tests.
    /// </summary>
    /// <param name="role">The endpoint role that owns the key schedule.</param>
    /// <param name="localPrivateKey">An optional P-256 private scalar to import for deterministic tests.</param>
    /// <param name="applicationProtocols">The configured ALPN protocols owned by this role.</param>
    internal QuicTlsKeySchedule(
        QuicTlsRole role,
        ReadOnlyMemory<byte> localPrivateKey = default,
        IReadOnlyList<SslApplicationProtocol>? applicationProtocols = null)
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

            deterministicClientHelloRandom = DeriveDeterministicClientHelloRandom(localPrivateKey.Span);
        }

        localKeyShare = ExportUncompressedPoint(localKeyPair.ExportParameters(true));
        this.applicationProtocols = NormalizeApplicationProtocols(applicationProtocols);
    }

    /// <summary>
    /// Gets the public local ephemeral key share associated with the current role's key pair.
    /// </summary>
    public ReadOnlyMemory<byte> LocalKeyShare => localKeyShare;

    /// <summary>
    /// Gets the derived resumption master secret, if the handshake has reached the point where it is available.
    /// </summary>
    internal ReadOnlyMemory<byte> ResumptionMasterSecret => resumptionMasterSecret ?? ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// Gets whether the current client ClientHello attempted PSK resumption and may surface 0-RTT material.
    /// </summary>
    internal bool ResumptionAttemptPending => resumptionAttemptPending;

    /// <summary>
    /// Configures whether the server role should emit a CertificateRequest and accept a client certificate response.
    /// </summary>
    internal void ConfigureServerClientAuthentication(bool clientCertificateRequired)
    {
        if (role == QuicTlsRole.Server)
        {
            serverClientCertificateRequired = clientCertificateRequired;
        }
    }

    internal bool TryConfigureLocalApplicationProtocols(IReadOnlyList<SslApplicationProtocol> applicationProtocols)
    {
        if (role != QuicTlsRole.Server)
        {
            return false;
        }

        byte[][] normalizedProtocols = NormalizeApplicationProtocols(applicationProtocols);
        if (normalizedProtocols.Length == 0)
        {
            return false;
        }

        if (this.applicationProtocols.Length == 0)
        {
            this.applicationProtocols = normalizedProtocols;
            return true;
        }

        return HaveSameApplicationProtocols(this.applicationProtocols, normalizedProtocols);
    }

    /// <summary>
    /// Creates the supported client Initial ClientHello transcript bytes for the current key share and transport parameters.
    /// </summary>
    internal bool TryCreateClientHello(QuicTransportParameters localTransportParameters, out byte[] clientHelloBytes)
        => TryCreateClientHello(localTransportParameters, detachedResumptionTicketSnapshot: null, nowTicks: 0, out clientHelloBytes);

    /// <summary>
    /// Creates the supported client Initial ClientHello transcript bytes for the current key share and transport parameters.
    /// </summary>
    internal bool TryCreateClientHello(
        QuicTransportParameters localTransportParameters,
        QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot,
        long nowTicks,
        out byte[] clientHelloBytes)
    {
        clientHelloBytes = Array.Empty<byte>();

        if (role != QuicTlsRole.Client)
        {
            return false;
        }

        byte[] transportParametersEncoded = new byte[512];
        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
            localTransportParameters,
            QuicTransportParameterRole.Client,
            transportParametersEncoded,
            out int transportParametersEncodedBytes))
        {
            return false;
        }

        int supportedVersionsExtensionLength = 2 + 2 + 1 + 2;
        int applicationProtocolsExtensionLength = GetApplicationLayerProtocolNegotiationExtensionLength(applicationProtocols);
        int signatureAlgorithmsExtensionLength = 2 + 2 + 2 + 2;
        int supportedGroupsExtensionLength = 2 + 2 + 2 + 2;
        int keyShareExtensionLength = 2 + 2 + 2 + 2 + 2 + localKeyShare.Length;
        int transportParametersExtensionLength = 2 + 2 + transportParametersEncodedBytes;
        int baseExtensionsLength = supportedVersionsExtensionLength
            + applicationProtocolsExtensionLength
            + signatureAlgorithmsExtensionLength
            + supportedGroupsExtensionLength
            + keyShareExtensionLength
            + transportParametersExtensionLength;

        if (CanAttemptResumption(detachedResumptionTicketSnapshot)
            && TryCreateResumptionClientHello(
                transportParametersEncoded.AsSpan(0, transportParametersEncodedBytes),
                baseExtensionsLength,
                detachedResumptionTicketSnapshot!,
                nowTicks,
                out clientHelloBytes))
        {
            resumptionAttemptPending = true;
            return true;
        }

        resumptionAttemptPending = false;
        return TryCreateInitialClientHello(
            transportParametersEncoded.AsSpan(0, transportParametersEncodedBytes),
            baseExtensionsLength,
            out clientHelloBytes);
    }

    /// <summary>
    /// Appends a local handshake message to the managed transcript without advancing peer state.
    /// </summary>
    internal void AppendLocalHandshakeMessage(ReadOnlySpan<byte> handshakeMessageBytes)
    {
        if (role == QuicTlsRole.Client
            && localHandshakeTranscriptPrefix is null
            && transcriptBytes.WrittenCount == 0
            && !handshakeMessageBytes.IsEmpty)
        {
            localHandshakeTranscriptPrefix = handshakeMessageBytes.ToArray();
        }

        AppendTranscriptMessage(handshakeMessageBytes);
    }

    internal bool TryResetClientPeerHandshakeAttempt()
    {
        if (role != QuicTlsRole.Client
            || localHandshakeTranscriptPrefix is null)
        {
            return false;
        }

        bool stateChanged = transcriptBytes.WrittenCount != localHandshakeTranscriptPrefix.Length
            || handshakeSecret is not null
            || clientHandshakeTrafficSecret is not null
            || serverHandshakeTrafficSecret is not null
            || resumptionMasterSecret is not null
            || clientApplicationTrafficSecret is not null
            || serverApplicationTrafficSecret is not null
            || peerLeafCertificateDer is not null
            || handshakeSecretsDerived
            || localServerFlightCompleted
            || peerCertificateVerifyVerified
            || peerFinishedVerified
            || isTerminal;

        transcriptBytes.Clear();
        transcriptBytes.Write(localHandshakeTranscriptPrefix);
        handshakeSecret = null;
        clientHandshakeTrafficSecret = null;
        serverHandshakeTrafficSecret = null;
        resumptionMasterSecret = null;
        clientApplicationTrafficSecret = null;
        serverApplicationTrafficSecret = null;
        peerLeafCertificateDer = null;
        handshakeSecretsDerived = false;
        localServerFlightCompleted = false;
        peerCertificateVerifyVerified = false;
        peerFinishedVerified = false;
        isTerminal = false;
        return stateChanged;
    }

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
    /// Copies the current managed handshake transcript bytes for focused tests.
    /// </summary>
    internal bool TryCopyHandshakeTranscriptBytes(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = transcriptBytes.WrittenCount;
        if (destination.Length < bytesWritten)
        {
            bytesWritten = 0;
            return false;
        }

        transcriptBytes.WrittenSpan.CopyTo(destination);
        return true;
    }

    /// <summary>
    /// Gets the peer Finished verify data for the current handshake transcript, if the handshake secret has been derived.
    /// </summary>
    internal bool TryGetExpectedPeerFinishedVerifyData(out byte[] verifyData)
    {
        verifyData = Array.Empty<byte>();

        ReadOnlySpan<byte> peerFinishedTrafficSecret = role == QuicTlsRole.Server
            ? clientHandshakeTrafficSecret ?? []
            : serverHandshakeTrafficSecret ?? [];

        if (peerFinishedTrafficSecret.IsEmpty
            || (role == QuicTlsRole.Server && !localServerFlightCompleted))
        {
            return false;
        }

        verifyData = DeriveFinishedVerifyData(peerFinishedTrafficSecret, HashTranscript());
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

    internal bool TryCreatePeerLeafCertificate(out X509Certificate2? certificate)
    {
        certificate = null;

        if (peerLeafCertificateDer is null)
        {
            return false;
        }

        try
        {
            certificate = X509CertificateLoader.LoadCertificate(peerLeafCertificateDer);
            return true;
        }
        catch (CryptographicException)
        {
            certificate = null;
            return false;
        }
    }

    /// <summary>
    /// Processes one handshake transcript step and returns any bridge-visible updates produced by the key schedule.
    /// </summary>
    internal IReadOnlyList<QuicTlsStateUpdate> ProcessTranscriptStep(QuicTlsTranscriptStep step)
    {
        return ProcessTranscriptStep(step, localTransportParameters: null);
    }

    /// <summary>
    /// Processes one handshake transcript step and returns any bridge-visible updates produced by the key schedule.
    /// </summary>
    internal IReadOnlyList<QuicTlsStateUpdate> ProcessTranscriptStep(
        QuicTlsTranscriptStep step,
        QuicTransportParameters? localTransportParameters,
        ReadOnlyMemory<byte> localServerLeafCertificateDer = default,
        ReadOnlyMemory<byte> localServerLeafSigningPrivateKey = default)
    {
        if (isTerminal || step.HandshakeMessageType is null || step.HandshakeMessageBytes.IsEmpty)
        {
            return Array.Empty<QuicTlsStateUpdate>();
        }

        if (role == QuicTlsRole.Server)
        {
            return step.HandshakeMessageType.Value switch
            {
                QuicTlsHandshakeMessageType.ClientHello => ProcessClientHello(
                    step,
                    localTransportParameters,
                    localServerLeafCertificateDer,
                    localServerLeafSigningPrivateKey),
                QuicTlsHandshakeMessageType.Certificate => ProcessCertificate(step),
                QuicTlsHandshakeMessageType.CertificateVerify => ProcessCertificateVerify(step),
                QuicTlsHandshakeMessageType.Finished => ProcessFinished(step),
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

    private IReadOnlyList<QuicTlsStateUpdate> ProcessClientHello(
        QuicTlsTranscriptStep step,
        QuicTransportParameters? localTransportParameters,
        ReadOnlyMemory<byte> localServerLeafCertificateDer,
        ReadOnlyMemory<byte> localServerLeafSigningPrivateKey)
    {
        byte[]? certificateBytes = null;
        byte[]? certificateRequestBytes = null;
        ECDsa? localServerLeafSigningKey = null;

        try
        {
            if (step.Kind == QuicTlsTranscriptStepKind.HelloRetryRequestRequested)
            {
                if (handshakeSecretsDerived
                    || serverHelloRetryRequestPending
                    || step.TranscriptPhase != QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage
                    || step.HandshakeMessageType != QuicTlsHandshakeMessageType.ClientHello
                    || step.HandshakeMessageLength is null
                    || step.TransportParameters is not null
                    || step.SelectedCipherSuite != profile.CipherSuite
                    || step.TranscriptHashAlgorithm != profile.TranscriptHashAlgorithm
                    || step.NamedGroup != profile.NamedGroup
                    || !step.KeyShare.IsEmpty
                    || localTransportParameters is null)
                {
                    return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
                }

                if (applicationProtocols.Length > 0
                    && !TryValidatePeerApplicationProtocolOffer(
                        step.HandshakeMessageBytes.Span,
                        out bool parseFailed))
                {
                    return BuildFatalAlert(
                        parseFailed
                            ? HandshakeTranscriptParseFailureAlertDescription
                            : NoApplicationProtocolAlertDescription);
                }

                if (!TryCreateHelloRetryRequest(step.HandshakeMessageBytes.Span, out byte[] helloRetryRequestBytes))
                {
                    return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
                }

                ReplaceTranscriptWithHelloRetryRequestPrefix(
                    step.HandshakeMessageBytes.Span,
                    helloRetryRequestBytes);
                serverHelloRetryRequestPending = true;

                ulong helloRetryRequestOffset = nextServerInitialCryptoOffset;
                nextServerInitialCryptoOffset = SaturatingAdd(
                    nextServerInitialCryptoOffset,
                    (ulong)helloRetryRequestBytes.Length);

                return
                [
                    new QuicTlsStateUpdate(
                        QuicTlsUpdateKind.CryptoDataAvailable,
                        QuicTlsEncryptionLevel.Initial,
                        CryptoDataOffset: helloRetryRequestOffset,
                        CryptoData: helloRetryRequestBytes),
                ];
            }

            if (handshakeSecretsDerived
                || step.Kind != QuicTlsTranscriptStepKind.PeerTransportParametersStaged
                || step.TranscriptPhase != QuicTlsTranscriptPhase.PeerTransportParametersStaged
                || step.HandshakeMessageType != QuicTlsHandshakeMessageType.ClientHello
                || step.HandshakeMessageLength is null
                || step.TransportParameters is null
                || step.SelectedCipherSuite != profile.CipherSuite
                || step.TranscriptHashAlgorithm != profile.TranscriptHashAlgorithm
                || step.NamedGroup != profile.NamedGroup
                || step.KeyShare.IsEmpty
                || localTransportParameters is null)
            {
                return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
            }

            ReadOnlySpan<byte> selectedApplicationProtocol = default;
            if (applicationProtocols.Length > 0)
            {
                if (!TrySelectPeerApplicationProtocol(
                    step.HandshakeMessageBytes.Span,
                    out byte[] selectedApplicationProtocolBytes,
                    out bool parseFailed))
                {
                    return BuildFatalAlert(
                        parseFailed
                            ? HandshakeTranscriptParseFailureAlertDescription
                            : NoApplicationProtocolAlertDescription);
                }

                selectedApplicationProtocol = selectedApplicationProtocolBytes;
            }

            if (!localServerLeafCertificateDer.IsEmpty
                && !TryCreateCertificate(localServerLeafCertificateDer.Span, out certificateBytes))
            {
                return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
            }

            if (!TryCreateServerLeafSigningKey(localServerLeafSigningPrivateKey.Span, out localServerLeafSigningKey))
            {
                return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
            }

            if (localServerLeafSigningKey is not null
                && !localServerLeafCertificateDer.IsEmpty
                && !TryValidateServerLeafSigningCompatibility(
                    localServerLeafCertificateDer.Span,
                    localServerLeafSigningKey))
            {
                return BuildFatalAlert(HandshakeTranscriptVerificationFailureAlertDescription);
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

            if (!TryCreateEncryptedExtensions(
                localTransportParameters,
                selectedApplicationProtocol,
                out byte[] encryptedExtensionsBytes))
            {
                return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
            }

            AppendTranscriptMessage(encryptedExtensionsBytes);
            ulong serverHelloOffset = nextServerInitialCryptoOffset;
            nextServerInitialCryptoOffset = SaturatingAdd(
                nextServerInitialCryptoOffset,
                (ulong)serverHelloBytes.Length);
            List<QuicTlsStateUpdate> updates =
            [
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    // After an optional HelloRetryRequest, ServerHello resumes at the next Initial CRYPTO offset.
                    QuicTlsEncryptionLevel.Initial,
                    CryptoDataOffset: serverHelloOffset,
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
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: encryptedExtensionsBytes),
            ];

            ulong certificateOffset = (ulong)encryptedExtensionsBytes.Length;
            if (serverClientCertificateRequired)
            {
                if (!TryCreateCertificateRequest(out certificateRequestBytes))
                {
                    return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
                }

                AppendTranscriptMessage(certificateRequestBytes);
                updates.Add(new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: certificateOffset,
                    CryptoData: certificateRequestBytes));

                certificateOffset += (ulong)certificateRequestBytes.Length;
            }

            if (certificateBytes is not null)
            {
                AppendTranscriptMessage(certificateBytes);
                updates.Add(new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: certificateOffset,
                    CryptoData: certificateBytes));
            }

            if (localServerLeafSigningKey is not null && certificateBytes is not null)
            {
                ReadOnlySpan<byte> transcriptHashAfterCertificate = HashTranscript();
                if (!TryCreateCertificateVerify(
                        localServerLeafSigningKey,
                        transcriptHashAfterCertificate,
                        out byte[] certificateVerifyBytes))
                {
                    return BuildFatalAlert(HandshakeTranscriptVerificationFailureAlertDescription);
                }

                ulong certificateVerifyOffset = certificateOffset + (ulong)certificateBytes.Length;
                AppendTranscriptMessage(certificateVerifyBytes);
                updates.Add(new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: certificateVerifyOffset,
                    CryptoData: certificateVerifyBytes));

                if (!TryCreateFinished(serverHandshakeTrafficSecret ?? [], HashTranscript(), out byte[] finishedBytes))
                {
                    return BuildFatalAlert(HandshakeTranscriptVerificationFailureAlertDescription);
                }

                ulong finishedOffset = certificateVerifyOffset + (ulong)certificateVerifyBytes.Length;
                AppendTranscriptMessage(finishedBytes);
                updates.Add(new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: finishedOffset,
                    CryptoData: finishedBytes));

                localServerFlightCompleted = true;
            }

            handshakeSecretsDerived = true;
            serverHelloRetryRequestPending = false;
            return updates;
        }
        finally
        {
            localServerLeafSigningKey?.Dispose();
        }
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

        if (resumptionAttemptPending)
        {
            resumptionAttemptPending = false;

            if (step.PreSharedKeySelected)
            {
                List<QuicTlsStateUpdate> acceptedUpdates =
                [
                    new QuicTlsStateUpdate(
                        QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
                        ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Accepted),
                ];

                ReadOnlySpan<byte> acceptedTranscriptHash = HashTranscript();
                if (!TryDeriveHandshakeTrafficSecrets(
                        step.KeyShare.Span,
                        acceptedTranscriptHash,
                        protectWithClientTrafficSecret: true,
                        out QuicTlsPacketProtectionMaterial acceptedOpenMaterial,
                        out QuicTlsPacketProtectionMaterial acceptedProtectMaterial))
                {
                    acceptedUpdates.AddRange(BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription));
                    return acceptedUpdates;
                }

                handshakeSecretsDerived = true;
                acceptedUpdates.Add(new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: acceptedOpenMaterial));
                acceptedUpdates.Add(new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: acceptedProtectMaterial));
                acceptedUpdates.Add(new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    QuicTlsEncryptionLevel.Handshake));
                return acceptedUpdates;
            }

            List<QuicTlsStateUpdate> rejectedUpdates =
            [
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable,
                    ResumptionAttemptDisposition: QuicTlsResumptionAttemptDisposition.Rejected),
            ];

            ReadOnlySpan<byte> transcriptHash = HashTranscript();
            if (!TryDeriveHandshakeTrafficSecrets(
                    step.KeyShare.Span,
                    transcriptHash,
                    protectWithClientTrafficSecret: true,
                    out QuicTlsPacketProtectionMaterial openMaterial,
                    out QuicTlsPacketProtectionMaterial protectMaterial))
            {
                rejectedUpdates.AddRange(BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription));
                return rejectedUpdates;
            }

            handshakeSecretsDerived = true;
            rejectedUpdates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: openMaterial));
            rejectedUpdates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: protectMaterial));
            rejectedUpdates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.KeysAvailable,
                QuicTlsEncryptionLevel.Handshake));
            return rejectedUpdates;
        }

        if (step.PreSharedKeySelected)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        ReadOnlySpan<byte> nonResumptionTranscriptHash = HashTranscript();
        if (!TryDeriveHandshakeTrafficSecrets(
                step.KeyShare.Span,
                nonResumptionTranscriptHash,
                protectWithClientTrafficSecret: true,
                out QuicTlsPacketProtectionMaterial nonResumptionOpenMaterial,
                out QuicTlsPacketProtectionMaterial nonResumptionProtectMaterial))
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        handshakeSecretsDerived = true;
        return
        [
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: nonResumptionOpenMaterial),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: nonResumptionProtectMaterial),
            new QuicTlsStateUpdate(
                QuicTlsUpdateKind.KeysAvailable,
                QuicTlsEncryptionLevel.Handshake),
        ];
    }

    private IReadOnlyList<QuicTlsStateUpdate> ProcessCertificate(QuicTlsTranscriptStep step)
    {
        if (role == QuicTlsRole.Server && !serverClientCertificateRequired)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

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
        if (role == QuicTlsRole.Server && !serverClientCertificateRequired)
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

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
        ReadOnlySpan<byte> peerFinishedTrafficSecret = role == QuicTlsRole.Server
            ? clientHandshakeTrafficSecret ?? []
            : serverHandshakeTrafficSecret ?? [];

        if (!handshakeSecretsDerived
            || peerFinishedTrafficSecret.IsEmpty
            || step.HandshakeMessageBytes.Length != HandshakeHeaderLength + HashLength
            || (role == QuicTlsRole.Server && !localServerFlightCompleted))
        {
            return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
        }

        ReadOnlySpan<byte> expectedFinished = step.HandshakeMessageBytes.Span.Slice(HandshakeHeaderLength, HashLength);
        ReadOnlySpan<byte> transcriptHash = HashTranscript();
        byte[] expectedVerifyData = DeriveFinishedVerifyData(peerFinishedTrafficSecret, transcriptHash);
        if (!expectedFinished.SequenceEqual(expectedVerifyData))
        {
            return BuildFatalAlert(HandshakeTranscriptVerificationFailureAlertDescription);
        }

        List<QuicTlsStateUpdate> updates = [];

        AppendTranscriptMessage(step.HandshakeMessageBytes.Span);

        peerFinishedVerified = true;
        updates.Add(new QuicTlsStateUpdate(QuicTlsUpdateKind.PeerFinishedVerified));

        if (role == QuicTlsRole.Client)
        {
            byte[] applicationTrafficTranscriptHash = HashTranscript();
            if (!TryCreateFinished(clientHandshakeTrafficSecret ?? [], applicationTrafficTranscriptHash, out byte[] finishedBytes))
            {
                return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
            }

            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.CryptoDataAvailable,
                QuicTlsEncryptionLevel.Handshake,
                CryptoDataOffset: 0,
                CryptoData: finishedBytes));

            QuicTlsPacketProtectionMaterial oneRttOpenMaterial = default;
            QuicTlsPacketProtectionMaterial oneRttProtectMaterial = default;
            byte[] resumptionTranscriptHash = HashTranscriptWithAppended(finishedBytes);
            if (!TryDeriveApplicationPacketProtectionMaterial(
                    applicationTrafficTranscriptHash,
                    resumptionTranscriptHash,
                    out oneRttOpenMaterial,
                    out oneRttProtectMaterial,
                    out byte[] derivedResumptionMasterSecret))
            {
                return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
            }

            this.resumptionMasterSecret = derivedResumptionMasterSecret;

            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.KeysAvailable,
                QuicTlsEncryptionLevel.OneRtt));
            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: oneRttOpenMaterial));
            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: oneRttProtectMaterial));
            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.ResumptionMasterSecretAvailable,
                ResumptionMasterSecret: derivedResumptionMasterSecret));
        }

        if (role == QuicTlsRole.Server)
        {
            byte[] applicationTrafficTranscriptHash = transcriptHash.ToArray();
            QuicTlsPacketProtectionMaterial oneRttOpenMaterial = default;
            QuicTlsPacketProtectionMaterial oneRttProtectMaterial = default;
            if (!TryDeriveApplicationPacketProtectionMaterial(
                applicationTrafficTranscriptHash,
                applicationTrafficTranscriptHash,
                out oneRttOpenMaterial,
                out oneRttProtectMaterial,
                out _))
            {
                return BuildFatalAlert(HandshakeTranscriptParseFailureAlertDescription);
            }

            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.KeysAvailable,
                QuicTlsEncryptionLevel.OneRtt));
            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: oneRttOpenMaterial));
            updates.Add(new QuicTlsStateUpdate(
                QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
                PacketProtectionMaterial: oneRttProtectMaterial));
        }

        if (role == QuicTlsRole.Client)
        {
            handshakeSecret = null;
        }

        return updates;
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

            sharedSecret = localKeyPair.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (CryptographicException)
        {
            return false;
        }

        byte[] earlySecret = HkdfExtract(ZeroHashInput, ZeroHashInput);
        byte[] derivedSecret = HkdfExpandLabel(earlySecret, DerivedLabel, EmptyTranscriptHash, HashLength);
        byte[] derivedHandshakeSecret = HkdfExtract(derivedSecret, sharedSecret);
        handshakeSecret = derivedHandshakeSecret;
        clientHandshakeTrafficSecret = HkdfExpandLabel(derivedHandshakeSecret, ClientHandshakeTrafficLabel, transcriptHash, HashLength);
        serverHandshakeTrafficSecret = HkdfExpandLabel(derivedHandshakeSecret, ServerHandshakeTrafficLabel, transcriptHash, HashLength);

        ReadOnlySpan<byte> openTrafficSecret = protectWithClientTrafficSecret
            ? serverHandshakeTrafficSecret
            : clientHandshakeTrafficSecret;
            ReadOnlySpan<byte> protectTrafficSecret = protectWithClientTrafficSecret
                ? clientHandshakeTrafficSecret
                : serverHandshakeTrafficSecret;

            if (!TryCreatePacketProtectionMaterial(
                QuicTlsEncryptionLevel.Handshake,
                openTrafficSecret,
                DeriveHeaderProtectionKey(openTrafficSecret),
                out openMaterial)
                || !TryCreatePacketProtectionMaterial(
                    QuicTlsEncryptionLevel.Handshake,
                    protectTrafficSecret,
                    DeriveHeaderProtectionKey(protectTrafficSecret),
                    out protectMaterial))
            {
                return false;
            }

        return true;
    }

    private bool TryDeriveApplicationPacketProtectionMaterial(
        ReadOnlySpan<byte> applicationTrafficTranscriptHash,
        ReadOnlySpan<byte> resumptionTranscriptHash,
        out QuicTlsPacketProtectionMaterial openMaterial,
        out QuicTlsPacketProtectionMaterial protectMaterial,
        out byte[] resumptionMasterSecret)
    {
        openMaterial = default;
        protectMaterial = default;
        resumptionMasterSecret = Array.Empty<byte>();

        if (handshakeSecret is null)
        {
            return false;
        }

        byte[] localHandshakeSecret = handshakeSecret;
        byte[]? derivedSecret = null;
        byte[]? masterSecret = null;
        byte[]? localResumptionMasterSecret = null;
        byte[]? localClientApplicationTrafficSecret = null;
        byte[]? localServerApplicationTrafficSecret = null;
        try
        {
            derivedSecret = HkdfExpandLabel(localHandshakeSecret, DerivedLabel, EmptyTranscriptHash, HashLength);
            masterSecret = HkdfExtract(derivedSecret, ZeroHashInput);
            localResumptionMasterSecret = HkdfExpandLabel(masterSecret, ResumptionMasterLabel, resumptionTranscriptHash, HashLength);
            localClientApplicationTrafficSecret = HkdfExpandLabel(
                masterSecret,
                ClientApplicationTrafficLabel,
                applicationTrafficTranscriptHash,
                HashLength);
            localServerApplicationTrafficSecret = HkdfExpandLabel(
                masterSecret,
                ServerApplicationTrafficLabel,
                applicationTrafficTranscriptHash,
                HashLength);

            ReadOnlySpan<byte> openTrafficSecret = role == QuicTlsRole.Client
                ? localServerApplicationTrafficSecret
                : localClientApplicationTrafficSecret;
            ReadOnlySpan<byte> protectTrafficSecret = role == QuicTlsRole.Client
                ? localClientApplicationTrafficSecret
                : localServerApplicationTrafficSecret;

            if (!TryCreatePacketProtectionMaterial(
                QuicTlsEncryptionLevel.OneRtt,
                openTrafficSecret,
                DeriveHeaderProtectionKey(openTrafficSecret),
                out openMaterial)
                || !TryCreatePacketProtectionMaterial(
                    QuicTlsEncryptionLevel.OneRtt,
                    protectTrafficSecret,
                    DeriveHeaderProtectionKey(protectTrafficSecret),
                    out protectMaterial))
            {
                return false;
            }

            this.resumptionMasterSecret = localResumptionMasterSecret;
            resumptionMasterSecret = localResumptionMasterSecret;
            clientApplicationTrafficSecret = localClientApplicationTrafficSecret;
            serverApplicationTrafficSecret = localServerApplicationTrafficSecret;
            localResumptionMasterSecret = null;
            localClientApplicationTrafficSecret = null;
            localServerApplicationTrafficSecret = null;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(localHandshakeSecret);
            if (derivedSecret is not null)
            {
                CryptographicOperations.ZeroMemory(derivedSecret);
            }

            if (masterSecret is not null)
            {
                CryptographicOperations.ZeroMemory(masterSecret);
            }

            if (localResumptionMasterSecret is not null)
            {
                CryptographicOperations.ZeroMemory(localResumptionMasterSecret);
            }

            if (localClientApplicationTrafficSecret is not null)
            {
                CryptographicOperations.ZeroMemory(localClientApplicationTrafficSecret);
            }

            if (localServerApplicationTrafficSecret is not null)
            {
                CryptographicOperations.ZeroMemory(localServerApplicationTrafficSecret);
            }

            handshakeSecret = null;
        }
    }

    internal bool TryDeriveOneRttSuccessorPacketProtectionMaterial(
        ReadOnlySpan<byte> currentOpenHeaderProtectionKey,
        ReadOnlySpan<byte> currentProtectHeaderProtectionKey,
        out QuicTlsPacketProtectionMaterial openMaterial,
        out QuicTlsPacketProtectionMaterial protectMaterial)
    {
        openMaterial = default;
        protectMaterial = default;

        if (!TryCreateOneRttSuccessorPacketProtectionUpdate(
                currentOpenHeaderProtectionKey,
                currentProtectHeaderProtectionKey,
                out QuicOneRttTrafficSecretUpdate update))
        {
            return false;
        }

        using (update)
        {
            openMaterial = update.OpenPacketProtectionMaterial;
            protectMaterial = update.ProtectPacketProtectionMaterial;
            return true;
        }
    }

    internal bool TryCreateOneRttSuccessorPacketProtectionUpdate(
        ReadOnlySpan<byte> currentOpenHeaderProtectionKey,
        ReadOnlySpan<byte> currentProtectHeaderProtectionKey,
        out QuicOneRttTrafficSecretUpdate update)
    {
        update = null!;

        if (clientApplicationTrafficSecret is null
            || serverApplicationTrafficSecret is null
            || currentOpenHeaderProtectionKey.Length == 0
            || currentProtectHeaderProtectionKey.Length == 0)
        {
            return false;
        }

        byte[] currentClientApplicationTrafficSecret = clientApplicationTrafficSecret;
        byte[] currentServerApplicationTrafficSecret = serverApplicationTrafficSecret;
        byte[]? nextClientApplicationTrafficSecret = null;
        byte[]? nextServerApplicationTrafficSecret = null;

        try
        {
            nextClientApplicationTrafficSecret = HkdfExpandLabel(
                currentClientApplicationTrafficSecret,
                QuicKeyUpdateLabel,
                [],
                HashLength);
            nextServerApplicationTrafficSecret = HkdfExpandLabel(
                currentServerApplicationTrafficSecret,
                QuicKeyUpdateLabel,
                [],
                HashLength);

            ReadOnlySpan<byte> openTrafficSecret = role == QuicTlsRole.Client
                ? nextServerApplicationTrafficSecret
                : nextClientApplicationTrafficSecret;
            ReadOnlySpan<byte> protectTrafficSecret = role == QuicTlsRole.Client
                ? nextClientApplicationTrafficSecret
                : nextServerApplicationTrafficSecret;

            if (!TryCreatePacketProtectionMaterial(
                QuicTlsEncryptionLevel.OneRtt,
                openTrafficSecret,
                currentOpenHeaderProtectionKey,
                out QuicTlsPacketProtectionMaterial openMaterial)
                || !TryCreatePacketProtectionMaterial(
                    QuicTlsEncryptionLevel.OneRtt,
                    protectTrafficSecret,
                    currentProtectHeaderProtectionKey,
                    out QuicTlsPacketProtectionMaterial protectMaterial))
            {
                return false;
            }

            update = new QuicOneRttTrafficSecretUpdate(
                nextClientApplicationTrafficSecret,
                nextServerApplicationTrafficSecret,
                openMaterial,
                protectMaterial);
            nextClientApplicationTrafficSecret = null;
            nextServerApplicationTrafficSecret = null;
            return true;
        }
        finally
        {
            if (nextClientApplicationTrafficSecret is not null)
            {
                CryptographicOperations.ZeroMemory(nextClientApplicationTrafficSecret);
            }

            if (nextServerApplicationTrafficSecret is not null)
            {
                CryptographicOperations.ZeroMemory(nextServerApplicationTrafficSecret);
            }
        }
    }

    internal bool TryCommitOneRttSuccessorTrafficSecrets(QuicOneRttTrafficSecretUpdate update)
    {
        if (clientApplicationTrafficSecret is null
            || serverApplicationTrafficSecret is null
            || !update.TryTakeApplicationTrafficSecrets(
                out byte[] nextClientApplicationTrafficSecret,
                out byte[] nextServerApplicationTrafficSecret))
        {
            return false;
        }

        CryptographicOperations.ZeroMemory(clientApplicationTrafficSecret);
        CryptographicOperations.ZeroMemory(serverApplicationTrafficSecret);
        clientApplicationTrafficSecret = nextClientApplicationTrafficSecret;
        serverApplicationTrafficSecret = nextServerApplicationTrafficSecret;
        return true;
    }

    internal bool TryDiscardOneRttApplicationTrafficSecrets()
    {
        if (clientApplicationTrafficSecret is null
            || serverApplicationTrafficSecret is null)
        {
            return false;
        }

        CryptographicOperations.ZeroMemory(clientApplicationTrafficSecret);
        CryptographicOperations.ZeroMemory(serverApplicationTrafficSecret);
        clientApplicationTrafficSecret = null;
        serverApplicationTrafficSecret = null;
        return true;
    }

    internal bool TryDeriveClientEarlyTrafficPacketProtectionMaterial(
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot,
        ReadOnlySpan<byte> clientHelloBytes,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        if (role != QuicTlsRole.Client
            || !resumptionAttemptPending
            || !detachedResumptionTicketSnapshot.HasResumptionCredentialMaterial
            || !detachedResumptionTicketSnapshot.HasEarlyDataPrerequisiteMaterial
            || detachedResumptionTicketSnapshot.ResumptionMasterSecret.Length != HashLength
            || clientHelloBytes.IsEmpty)
        {
            return false;
        }

        ReadOnlySpan<byte> detachedResumptionMasterSecret = detachedResumptionTicketSnapshot.ResumptionMasterSecret.Span;
        ReadOnlySpan<byte> ticketNonce = detachedResumptionTicketSnapshot.TicketNonce.Span;
        byte[]? resumptionPsk = null;
        byte[]? earlySecret = null;
        byte[]? clientEarlyTrafficSecret = null;

        try
        {
            resumptionPsk = HkdfExpandLabel(detachedResumptionMasterSecret, ResumptionLabel, ticketNonce, HashLength);
            earlySecret = HkdfExtract(ZeroHashInput, resumptionPsk);
            byte[] clientHelloTranscriptHash = SHA256.HashData(clientHelloBytes);
            clientEarlyTrafficSecret = HkdfExpandLabel(earlySecret, ClientEarlyTrafficLabel, clientHelloTranscriptHash, HashLength);

            return TryCreatePacketProtectionMaterial(
                QuicTlsEncryptionLevel.ZeroRtt,
                clientEarlyTrafficSecret,
                DeriveHeaderProtectionKey(clientEarlyTrafficSecret),
                out material);
        }
        finally
        {
            if (resumptionPsk is not null)
            {
                CryptographicOperations.ZeroMemory(resumptionPsk);
            }

            if (earlySecret is not null)
            {
                CryptographicOperations.ZeroMemory(earlySecret);
            }

            if (clientEarlyTrafficSecret is not null)
            {
                CryptographicOperations.ZeroMemory(clientEarlyTrafficSecret);
            }
        }
    }

    private static bool TryCreatePacketProtectionMaterial(
        QuicTlsEncryptionLevel encryptionLevel,
        ReadOnlySpan<byte> trafficSecret,
        ReadOnlySpan<byte> headerProtectionKey,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        byte[] aeadKey = HkdfExpandLabel(trafficSecret, QuicKeyLabel, [], 16);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, QuicIvLabel, [], 12);

        return QuicTlsPacketProtectionMaterial.TryCreate(
            encryptionLevel,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            PacketProtectionUsageLimits,
            out material);
    }

    private static QuicAeadUsageLimits CreatePacketProtectionUsageLimits()
    {
        if (!QuicAeadUsageLimitCalculator.TryGetUsageLimits(
                QuicAeadAlgorithm.Aes128Gcm,
                QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
                QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
                out QuicAeadUsageLimits usageLimits))
        {
            throw new InvalidOperationException("The supported packet-protection usage limits are unavailable.");
        }

        return usageLimits;
    }

    private static byte[] DeriveHeaderProtectionKey(ReadOnlySpan<byte> trafficSecret)
    {
        return HkdfExpandLabel(trafficSecret, QuicHpLabel, [], HeaderProtectionKeyLength);
    }

    private bool TryCreateInitialClientHello(
        ReadOnlySpan<byte> transportParametersEncoded,
        int baseExtensionsLength,
        out byte[] clientHelloBytes)
    {
        int extensionsLength = baseExtensionsLength;
        byte[] body = new byte[43 + extensionsLength];
        WriteClientHelloPrefix(body, extensionsLength, out int index);
        WriteClientHelloBaseExtensions(body, ref index, transportParametersEncoded);
        clientHelloBytes = WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
        return true;
    }

    private bool TryCreateResumptionClientHello(
        ReadOnlySpan<byte> transportParametersEncoded,
        int baseExtensionsLength,
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot,
        long nowTicks,
        out byte[] clientHelloBytes)
    {
        clientHelloBytes = Array.Empty<byte>();

        ReadOnlySpan<byte> ticketBytes = detachedResumptionTicketSnapshot.TicketBytes.Span;
        ReadOnlySpan<byte> ticketNonce = detachedResumptionTicketSnapshot.TicketNonce.Span;
        ReadOnlySpan<byte> detachedResumptionMasterSecret = detachedResumptionTicketSnapshot.ResumptionMasterSecret.Span;
        if (ticketBytes.IsEmpty
            || detachedResumptionMasterSecret.Length != HashLength
            || ticketBytes.Length > ushort.MaxValue)
        {
            return false;
        }

        int pskIdentityLength = UInt16Length + ticketBytes.Length + sizeof(uint);
        int identitiesVectorLength = pskIdentityLength;
        int binderEntryLength = 1 + HashLength;
        int bindersVectorLength = binderEntryLength;
        int pskModesExtensionLength = UInt16Length + UInt16Length + 1 + PskKeyExchangeModesVectorLength;
        int preSharedKeyExtensionLength = UInt16Length
            + identitiesVectorLength
            + UInt16Length
            + bindersVectorLength;
        int extensionsLength = baseExtensionsLength
            + pskModesExtensionLength
            + (UInt16Length + UInt16Length + preSharedKeyExtensionLength);

        byte[] body = new byte[43 + extensionsLength];
        WriteClientHelloPrefix(body, extensionsLength, out int index);
        WriteClientHelloBaseExtensions(body, ref index, transportParametersEncoded);

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), PskKeyExchangeModesExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)(1 + PskKeyExchangeModesVectorLength)));
        index += UInt16Length;
        body[index++] = PskKeyExchangeModesVectorLength;
        body[index++] = PskDheKeMode;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), PreSharedKeyExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)preSharedKeyExtensionLength));
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)identitiesVectorLength));
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)ticketBytes.Length));
        index += UInt16Length;
        ticketBytes.CopyTo(body.AsSpan(index, ticketBytes.Length));
        index += ticketBytes.Length;
        BinaryPrimitives.WriteUInt32BigEndian(
            body.AsSpan(index, sizeof(uint)),
            ComputeObfuscatedTicketAge(detachedResumptionTicketSnapshot, nowTicks));
        index += sizeof(uint);

        int truncatedBodyLength = index;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)bindersVectorLength));
        index += UInt16Length;
        body[index++] = HashLength;
        int binderOffset = index;

        byte[] partialClientHello = WrapHandshakeMessagePrefix(
            QuicTlsHandshakeMessageType.ClientHello,
            body.Length,
            body.AsSpan(0, truncatedBodyLength));

        byte[]? resumptionPsk = null;
        byte[]? earlySecret = null;
        byte[]? binderKey = null;

        try
        {
            resumptionPsk = HkdfExpandLabel(detachedResumptionMasterSecret, ResumptionLabel, ticketNonce, HashLength);
            earlySecret = HkdfExtract(ZeroHashInput, resumptionPsk);
            binderKey = HkdfExpandLabel(earlySecret, ResumptionBinderLabel, EmptyTranscriptHash, HashLength);
            byte[] partialTranscriptHash = SHA256.HashData(partialClientHello);
            byte[] binder = DeriveFinishedVerifyData(binderKey, partialTranscriptHash);
            binder.CopyTo(body.AsSpan(binderOffset, HashLength));
        }
        finally
        {
            if (resumptionPsk is not null)
            {
                CryptographicOperations.ZeroMemory(resumptionPsk);
            }

            if (earlySecret is not null)
            {
                CryptographicOperations.ZeroMemory(earlySecret);
            }

            if (binderKey is not null)
            {
                CryptographicOperations.ZeroMemory(binderKey);
            }
        }

        clientHelloBytes = WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
        return true;
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

    private bool TryCreateHelloRetryRequest(
        ReadOnlySpan<byte> clientHelloBytes,
        out byte[] helloRetryRequestBytes)
    {
        helloRetryRequestBytes = Array.Empty<byte>();

        if (!TryParseClientHelloSessionId(clientHelloBytes, out byte[] sessionId))
        {
            return false;
        }

        int sessionIdLength = sessionId.Length;
        int selectedGroupExtensionLength = UInt16Length;
        int extensionsLength =
            (UInt16Length + UInt16Length + UInt16Length)
            + (UInt16Length + UInt16Length + selectedGroupExtensionLength);
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
        HelloRetryRequestRandom.CopyTo(body, index);
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
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)selectedGroupExtensionLength));
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), Secp256r1NamedGroup);

        helloRetryRequestBytes = WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
        return true;
    }

    private static bool TryCreateEncryptedExtensions(
        QuicTransportParameters localTransportParameters,
        ReadOnlySpan<byte> selectedApplicationProtocol,
        out byte[] encryptedExtensionsBytes)
    {
        encryptedExtensionsBytes = Array.Empty<byte>();

        Span<byte> encodedTransportParameters = stackalloc byte[512];
        if (!QuicTransportParametersCodec.TryFormatTransportParameters(
            localTransportParameters,
            QuicTransportParameterRole.Server,
            encodedTransportParameters,
            out int encodedTransportParametersBytes))
        {
            return false;
        }

        int transportParametersExtensionLength = checked(UInt16Length + UInt16Length + encodedTransportParametersBytes);
        int applicationProtocolExtensionLength = GetApplicationLayerProtocolNegotiationExtensionLength(selectedApplicationProtocol);
        int extensionsLength = checked(transportParametersExtensionLength + applicationProtocolExtensionLength);
        int messageBodyLength = checked(UInt16Length + extensionsLength);

        byte[] body = new byte[messageBodyLength];
        int index = 0;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)extensionsLength));
        index += UInt16Length;

        BinaryPrimitives.WriteUInt16BigEndian(
            body.AsSpan(index, UInt16Length),
            QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)encodedTransportParametersBytes));
        index += UInt16Length;
        encodedTransportParameters[..encodedTransportParametersBytes].CopyTo(body.AsSpan(index, encodedTransportParametersBytes));
        index += encodedTransportParametersBytes;

        WriteApplicationLayerProtocolNegotiationExtension(selectedApplicationProtocol, body, ref index);

        if (index != body.Length)
        {
            return false;
        }

        encryptedExtensionsBytes = WrapHandshakeMessage(QuicTlsHandshakeMessageType.EncryptedExtensions, body);
        return true;
    }

    private static bool TryCreateCertificateRequest(out byte[] certificateRequestBytes)
    {
        certificateRequestBytes = Array.Empty<byte>();

        Span<byte> body = stackalloc byte[11];
        int index = 0;

        body[index++] = (byte)CertificateRequestContextLength;
        BinaryPrimitives.WriteUInt16BigEndian(body.Slice(index, UInt16Length), CertificateRequestExtensionsLength);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(
            body.Slice(index, UInt16Length),
            CertificateRequestSignatureAlgorithmsExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(
            body.Slice(index, UInt16Length),
            CertificateRequestSignatureAlgorithmsExtensionLength);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(
            body.Slice(index, UInt16Length),
            CertificateRequestSignatureSchemeListLength);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(
            body.Slice(index, UInt16Length),
            (ushort)QuicTlsSignatureScheme.EcdsaSecp256r1Sha256);

        certificateRequestBytes = WrapHandshakeMessage(QuicTlsHandshakeMessageType.CertificateRequest, body);
        return true;
    }

    private static bool TryCreateCertificate(ReadOnlySpan<byte> leafCertificateDer, out byte[] certificateBytes)
    {
        certificateBytes = Array.Empty<byte>();

        if (leafCertificateDer.IsEmpty)
        {
            return false;
        }

        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(leafCertificateDer.ToArray());
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

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), 0);

        certificateBytes = WrapHandshakeMessage(QuicTlsHandshakeMessageType.Certificate, body);
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
        => WrapHandshakeMessage((byte)messageType, body);

    private static byte[] WrapHandshakeMessage(byte messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[HandshakeHeaderLength + body.Length];
        transcript[0] = messageType;
        WriteUInt24(transcript.AsSpan(1, UInt24Length), body.Length);
        body.CopyTo(transcript.AsSpan(HandshakeHeaderLength));
        return transcript;
    }

    private static byte[] WrapHandshakeMessagePrefix(
        QuicTlsHandshakeMessageType messageType,
        int fullBodyLength,
        ReadOnlySpan<byte> bodyPrefix)
    {
        byte[] transcript = new byte[HandshakeHeaderLength + bodyPrefix.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, UInt24Length), fullBodyLength);
        bodyPrefix.CopyTo(transcript.AsSpan(HandshakeHeaderLength));
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
            ReadOnlySpan<byte> certificateVerifyContext = role == QuicTlsRole.Server
                ? ClientCertificateVerifyContext
                : ServerCertificateVerifyContext;
            Span<byte> signedData = stackalloc byte[CertificateVerifyContextPrefixLength
                + certificateVerifyContext.Length
                + 1
                + HashLength];
            signedData[..CertificateVerifyContextPrefixLength].Fill(CertificateVerifySignedDataPrefixByte);
            certificateVerifyContext.CopyTo(signedData.Slice(CertificateVerifyContextPrefixLength));
            signedData[CertificateVerifyContextPrefixLength + certificateVerifyContext.Length] = 0x00;
            transcriptHash.AsSpan().CopyTo(
                signedData.Slice(CertificateVerifyContextPrefixLength + certificateVerifyContext.Length + 1));

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

    private bool TryValidatePeerApplicationProtocolOffer(
        ReadOnlySpan<byte> clientHelloBytes,
        out bool parseFailed)
    {
        parseFailed = false;

        if (!TryReadClientHelloApplicationProtocols(
            clientHelloBytes,
            out byte[][] peerApplicationProtocols,
            out ClientHelloApplicationProtocolOfferState offerState))
        {
            parseFailed = true;
            return false;
        }

        return offerState == ClientHelloApplicationProtocolOfferState.Present
            && TrySelectConfiguredApplicationProtocol(peerApplicationProtocols, out _);
    }

    private bool TrySelectPeerApplicationProtocol(
        ReadOnlySpan<byte> clientHelloBytes,
        out byte[] selectedApplicationProtocol,
        out bool parseFailed)
    {
        selectedApplicationProtocol = Array.Empty<byte>();
        parseFailed = false;

        if (!TryReadClientHelloApplicationProtocols(
            clientHelloBytes,
            out byte[][] peerApplicationProtocols,
            out ClientHelloApplicationProtocolOfferState offerState))
        {
            parseFailed = true;
            return false;
        }

        return offerState == ClientHelloApplicationProtocolOfferState.Present
            && TrySelectConfiguredApplicationProtocol(peerApplicationProtocols, out selectedApplicationProtocol);
    }

    private bool TrySelectConfiguredApplicationProtocol(
        IReadOnlyList<byte[]> peerApplicationProtocols,
        out byte[] selectedApplicationProtocol)
    {
        selectedApplicationProtocol = Array.Empty<byte>();

        foreach (byte[] localApplicationProtocol in applicationProtocols)
        {
            foreach (byte[] peerApplicationProtocol in peerApplicationProtocols)
            {
                if (localApplicationProtocol.AsSpan().SequenceEqual(peerApplicationProtocol))
                {
                    selectedApplicationProtocol = localApplicationProtocol;
                    return true;
                }
            }
        }

        return false;
    }

    private static bool TryReadClientHelloApplicationProtocols(
        ReadOnlySpan<byte> clientHelloBytes,
        out byte[][] applicationProtocols,
        out ClientHelloApplicationProtocolOfferState offerState)
    {
        applicationProtocols = [];
        offerState = ClientHelloApplicationProtocolOfferState.Missing;

        if (clientHelloBytes.Length <= HandshakeHeaderLength
            || clientHelloBytes[0] != (byte)QuicTlsHandshakeMessageType.ClientHello)
        {
            return false;
        }

        int declaredBodyLength = checked((int)ReadUInt24(clientHelloBytes.Slice(1, UInt24Length)));
        if (declaredBodyLength != clientHelloBytes.Length - HandshakeHeaderLength)
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
            || !TrySkipBytes(clientHelloBody, ref index, sessionIdLength)
            || !TryReadUInt16(clientHelloBody, ref index, out ushort cipherSuitesLength)
            || cipherSuitesLength < TlsCipherSuitesListLength
            || (cipherSuitesLength & 1) != 0
            || !TrySkipBytes(clientHelloBody, ref index, cipherSuitesLength)
            || !TryReadUInt8(clientHelloBody, ref index, out int compressionMethodsLength)
            || compressionMethodsLength != 1
            || !TryReadUInt8(clientHelloBody, ref index, out int compressionMethod)
            || compressionMethod != NullCompressionMethod
            || !TryReadUInt16(clientHelloBody, ref index, out ushort extensionsLength)
            || !TrySkipBytes(clientHelloBody, ref index, extensionsLength)
            || index != clientHelloBody.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> extensions = clientHelloBody.Slice(clientHelloBody.Length - extensionsLength, extensionsLength);
        int extensionsIndex = 0;
        while (extensionsIndex < extensions.Length)
        {
            if (!TryReadUInt16(extensions, ref extensionsIndex, out ushort extensionType)
                || !TryReadUInt16(extensions, ref extensionsIndex, out ushort extensionLength)
                || !TrySkipBytes(extensions, ref extensionsIndex, extensionLength))
            {
                return false;
            }

            if (extensionType != ApplicationLayerProtocolNegotiationExtensionType)
            {
                continue;
            }

            if (offerState != ClientHelloApplicationProtocolOfferState.Missing)
            {
                offerState = ClientHelloApplicationProtocolOfferState.Invalid;
                return true;
            }

            if (!TryReadApplicationLayerProtocolOfferList(
                extensions.Slice(extensionsIndex - extensionLength, extensionLength),
                out applicationProtocols))
            {
                offerState = ClientHelloApplicationProtocolOfferState.Invalid;
                applicationProtocols = [];
                return true;
            }

            offerState = ClientHelloApplicationProtocolOfferState.Present;
        }

        return true;
    }

    private static bool TryReadApplicationLayerProtocolOfferList(
        ReadOnlySpan<byte> extensionValue,
        out byte[][] applicationProtocols)
    {
        applicationProtocols = [];

        int index = 0;
        if (!TryReadUInt16(extensionValue, ref index, out ushort protocolNameListLength)
            || protocolNameListLength == 0
            || index + protocolNameListLength != extensionValue.Length)
        {
            return false;
        }

        List<byte[]> offeredProtocols = [];
        int protocolListEnd = index + protocolNameListLength;
        while (index < protocolListEnd)
        {
            if (!TryReadUInt8(extensionValue, ref index, out int protocolNameLength)
                || protocolNameLength == 0
                || !TrySkipBytes(extensionValue, ref index, protocolNameLength))
            {
                return false;
            }

            byte[] protocolName = extensionValue.Slice(index - protocolNameLength, protocolNameLength).ToArray();
            if (ContainsApplicationProtocol(offeredProtocols, protocolName))
            {
                return false;
            }

            offeredProtocols.Add(protocolName);
        }

        if (index != extensionValue.Length || offeredProtocols.Count == 0)
        {
            return false;
        }

        applicationProtocols = [.. offeredProtocols];
        return true;
    }

    private static bool ContainsApplicationProtocol(IReadOnlyList<byte[]> applicationProtocols, ReadOnlySpan<byte> candidate)
    {
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            if (applicationProtocol.AsSpan().SequenceEqual(candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryValidateEcdsaP256PublicKey(ECDsa publicKey)
    {
        return TryGetEcdsaP256PublicKeyParameters(publicKey, out _);
    }

    private static bool TryGetEcdsaP256PublicKeyParameters(
        ECDsa publicKey,
        out ECParameters parameters)
    {
        parameters = default;

        if (publicKey.KeySize != EcdsaP256KeySizeBits)
        {
            return false;
        }

        try
        {
            parameters = publicKey.ExportParameters(false);
            return parameters.Curve.IsNamed
                && parameters.Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value
                && parameters.Q.X is not null
                && parameters.Q.Y is not null;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryCreateServerLeafSigningKey(
        ReadOnlySpan<byte> localServerLeafSigningPrivateKey,
        out ECDsa? signingKey)
    {
        signingKey = null;

        if (localServerLeafSigningPrivateKey.IsEmpty)
        {
            return true;
        }

        try
        {
            ECDsa createdSigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            createdSigningKey.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = localServerLeafSigningPrivateKey.ToArray(),
            });

            if (!TryValidateEcdsaP256PublicKey(createdSigningKey))
            {
                createdSigningKey.Dispose();
                return false;
            }

            signingKey = createdSigningKey;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryValidateServerLeafSigningCompatibility(
        ReadOnlySpan<byte> localServerLeafCertificateDer,
        ECDsa serverLeafSigningKey)
    {
        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(localServerLeafCertificateDer.ToArray());
            using ECDsa? certificatePublicKey = certificate.GetECDsaPublicKey();
            if (certificatePublicKey is null
                || !TryGetEcdsaP256PublicKeyParameters(certificatePublicKey, out ECParameters certificateParameters)
                || !TryGetEcdsaP256PublicKeyParameters(serverLeafSigningKey, out ECParameters signingParameters))
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(certificateParameters.Q.X!, signingParameters.Q.X!)
                && CryptographicOperations.FixedTimeEquals(certificateParameters.Q.Y!, signingParameters.Q.Y!);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryCreateCertificateVerify(
        ECDsa serverLeafSigningKey,
        ReadOnlySpan<byte> transcriptHash,
        out byte[] certificateVerifyBytes)
    {
        certificateVerifyBytes = Array.Empty<byte>();

        Span<byte> signedData = stackalloc byte[CertificateVerifyContextPrefixLength
            + ServerCertificateVerifyContext.Length
            + 1
            + transcriptHash.Length];
        signedData[..CertificateVerifyContextPrefixLength].Fill(CertificateVerifySignedDataPrefixByte);
        ServerCertificateVerifyContext.CopyTo(signedData.Slice(CertificateVerifyContextPrefixLength));
        signedData[CertificateVerifyContextPrefixLength + ServerCertificateVerifyContext.Length] = 0x00;
        transcriptHash.CopyTo(
            signedData.Slice(CertificateVerifyContextPrefixLength + ServerCertificateVerifyContext.Length + 1));

        try
        {
            byte[] signature = serverLeafSigningKey.SignData(
                signedData,
                HashAlgorithmName.SHA256,
                CertificateVerifySignatureFormat);

            int bodyLength = checked(UInt16Length + UInt16Length + signature.Length);
            byte[] body = new byte[bodyLength];
            int index = 0;

            BinaryPrimitives.WriteUInt16BigEndian(
                body.AsSpan(index, UInt16Length),
                (ushort)QuicTlsSignatureScheme.EcdsaSecp256r1Sha256);
            index += UInt16Length;
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)signature.Length));
            index += UInt16Length;
            signature.CopyTo(body.AsSpan(index, signature.Length));

            certificateVerifyBytes = WrapHandshakeMessage(QuicTlsHandshakeMessageType.CertificateVerify, body);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private bool TryCreateFinished(ReadOnlySpan<byte> trafficSecret, ReadOnlySpan<byte> transcriptHash, out byte[] finishedBytes)
    {
        finishedBytes = Array.Empty<byte>();

        if (trafficSecret.IsEmpty)
        {
            return false;
        }

        finishedBytes = WrapHandshakeMessage(
            QuicTlsHandshakeMessageType.Finished,
            DeriveFinishedVerifyData(trafficSecret, transcriptHash));
        return true;
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

    private void ReplaceTranscriptWithHelloRetryRequestPrefix(
        ReadOnlySpan<byte> initialClientHelloBytes,
        ReadOnlySpan<byte> helloRetryRequestBytes)
    {
        byte[] initialClientHelloHash = SHA256.HashData(initialClientHelloBytes.ToArray());
        byte[] messageHashBytes = WrapHandshakeMessage(MessageHashHandshakeType, initialClientHelloHash);

        transcriptBytes.Clear();
        transcriptBytes.Write(messageHashBytes);
        transcriptBytes.Write(helloRetryRequestBytes);
    }

    private byte[] HashTranscript()
    {
        return SHA256.HashData(transcriptBytes.WrittenSpan);
    }

    private byte[] HashTranscriptWithAppended(ReadOnlySpan<byte> handshakeMessageBytes)
    {
        return SHA256.HashData([.. transcriptBytes.WrittenSpan, .. handshakeMessageBytes]);
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
        serverHelloRetryRequestPending = false;
        nextServerInitialCryptoOffset = 0;
        if (handshakeSecret is not null)
        {
            CryptographicOperations.ZeroMemory(handshakeSecret);
            handshakeSecret = null;
        }
        if (resumptionMasterSecret is not null)
        {
            CryptographicOperations.ZeroMemory(resumptionMasterSecret);
            resumptionMasterSecret = null;
        }
        if (clientApplicationTrafficSecret is not null)
        {
            CryptographicOperations.ZeroMemory(clientApplicationTrafficSecret);
            clientApplicationTrafficSecret = null;
        }
        if (serverApplicationTrafficSecret is not null)
        {
            CryptographicOperations.ZeroMemory(serverApplicationTrafficSecret);
            serverApplicationTrafficSecret = null;
        }
        peerLeafCertificateDer = null;
        peerCertificateVerifyVerified = false;
        return [new QuicTlsStateUpdate(QuicTlsUpdateKind.FatalAlert, AlertDescription: alertDescription)];
    }

    private static ulong SaturatingAdd(ulong left, ulong right)
    {
        ulong sum = left + right;
        return sum < left ? ulong.MaxValue : sum;
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

    private static bool CanAttemptResumption(QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot)
        => detachedResumptionTicketSnapshot is not null
            && detachedResumptionTicketSnapshot.HasResumptionCredentialMaterial
            && detachedResumptionTicketSnapshot.TicketLifetimeSeconds > 0
            && !detachedResumptionTicketSnapshot.TicketBytes.IsEmpty
            && detachedResumptionTicketSnapshot.ResumptionMasterSecret.Length == HashLength;

    private void WriteClientHelloPrefix(byte[] body, int extensionsLength, out int index)
    {
        index = 0;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), TlsLegacyVersion);
        index += UInt16Length;

        Span<byte> clientRandom = body.AsSpan(index, TlsRandomLength);
        if (deterministicClientHelloRandom is { Length: TlsRandomLength } deterministicRandom)
        {
            deterministicRandom.CopyTo(clientRandom);
        }
        else
        {
            RandomNumberGenerator.Fill(clientRandom);
        }

        index += TlsRandomLength;

        body[index++] = 0x00;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), TlsCipherSuitesListLength);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), (ushort)profile.CipherSuite);
        index += UInt16Length;

        body[index++] = 1;
        body[index++] = NullCompressionMethod;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)extensionsLength));
        index += UInt16Length;
    }

    private static byte[] DeriveDeterministicClientHelloRandom(ReadOnlySpan<byte> localPrivateKey)
    {
        byte[] seedMaterial = GC.AllocateUninitializedArray<byte>(
            DeterministicClientHelloRandomLabel.Length + localPrivateKey.Length);
        DeterministicClientHelloRandomLabel.CopyTo(seedMaterial, 0);
        localPrivateKey.CopyTo(seedMaterial.AsSpan(DeterministicClientHelloRandomLabel.Length));
        return SHA256.HashData(seedMaterial);
    }

    private void WriteClientHelloBaseExtensions(
        byte[] body,
        ref int index,
        ReadOnlySpan<byte> transportParametersEncoded)
    {
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SupportedVersionsExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SupportedVersionsExtensionBodyLength);
        index += UInt16Length;
        body[index++] = SupportedVersionsVectorLength;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), Tls13Version);
        index += UInt16Length;

        WriteClientHelloApplicationProtocolNegotiationExtension(body, ref index);

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SignatureAlgorithmsExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SignatureAlgorithmsExtensionBodyLength);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SignatureAlgorithmsVectorLength);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(
            body.AsSpan(index, UInt16Length),
            (ushort)QuicTlsSignatureScheme.EcdsaSecp256r1Sha256);
        index += UInt16Length;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SupportedGroupsExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SupportedGroupsExtensionBodyLength);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), SupportedGroupsVectorLength);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), Secp256r1NamedGroup);
        index += UInt16Length;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), KeyShareExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)(UInt16Length + KeyShareEntryFixedLength + localKeyShare.Length)));
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)(KeyShareEntryFixedLength + localKeyShare.Length)));
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), Secp256r1NamedGroup);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)localKeyShare.Length));
        index += UInt16Length;
        localKeyShare.CopyTo(body, index);
        index += localKeyShare.Length;

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)transportParametersEncoded.Length));
        index += UInt16Length;
        transportParametersEncoded.CopyTo(body.AsSpan(index, transportParametersEncoded.Length));
        index += transportParametersEncoded.Length;
    }

    private void WriteClientHelloApplicationProtocolNegotiationExtension(byte[] body, ref int index)
    {
        if (applicationProtocols.Length == 0)
        {
            return;
        }

        WriteApplicationLayerProtocolNegotiationExtension(applicationProtocols, body, ref index);
    }

    private static int GetApplicationLayerProtocolNegotiationExtensionLength(IReadOnlyList<byte[]> applicationProtocols)
    {
        if (applicationProtocols.Count == 0)
        {
            return 0;
        }

        int protocolListLength = 0;
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            protocolListLength = checked(protocolListLength + 1 + applicationProtocol.Length);
        }

        return checked(UInt16Length + UInt16Length + UInt16Length + protocolListLength);
    }

    private static int GetApplicationLayerProtocolNegotiationExtensionLength(ReadOnlySpan<byte> applicationProtocol)
    {
        if (applicationProtocol.IsEmpty)
        {
            return 0;
        }

        return checked(UInt16Length + UInt16Length + UInt16Length + 1 + applicationProtocol.Length);
    }

    private static void WriteApplicationLayerProtocolNegotiationExtension(
        IReadOnlyList<byte[]> applicationProtocols,
        byte[] body,
        ref int index)
    {
        int protocolListLength = 0;
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            protocolListLength = checked(protocolListLength + 1 + applicationProtocol.Length);
        }

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), ApplicationLayerProtocolNegotiationExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)(UInt16Length + protocolListLength)));
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)protocolListLength));
        index += UInt16Length;

        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            body[index++] = checked((byte)applicationProtocol.Length);
            applicationProtocol.CopyTo(body, index);
            index += applicationProtocol.Length;
        }
    }

    private static void WriteApplicationLayerProtocolNegotiationExtension(
        ReadOnlySpan<byte> applicationProtocol,
        byte[] body,
        ref int index)
    {
        if (applicationProtocol.IsEmpty)
        {
            return;
        }

        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), ApplicationLayerProtocolNegotiationExtensionType);
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)(UInt16Length + 1 + applicationProtocol.Length)));
        index += UInt16Length;
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(index, UInt16Length), checked((ushort)(1 + applicationProtocol.Length)));
        index += UInt16Length;
        body[index++] = checked((byte)applicationProtocol.Length);
        applicationProtocol.CopyTo(body.AsSpan(index, applicationProtocol.Length));
        index += applicationProtocol.Length;
    }

    private static byte[][] NormalizeApplicationProtocols(IReadOnlyList<SslApplicationProtocol>? applicationProtocols)
    {
        if (applicationProtocols is null || applicationProtocols.Count == 0)
        {
            return [];
        }

        byte[][] normalizedProtocols = new byte[applicationProtocols.Count][];
        for (int index = 0; index < applicationProtocols.Count; index++)
        {
            normalizedProtocols[index] = applicationProtocols[index].Protocol.ToArray();
        }

        return normalizedProtocols;
    }

    private static bool HaveSameApplicationProtocols(
        IReadOnlyList<byte[]> left,
        IReadOnlyList<byte[]> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        for (int index = 0; index < left.Count; index++)
        {
            if (!left[index].AsSpan().SequenceEqual(right[index]))
            {
                return false;
            }
        }

        return true;
    }

    private static uint ComputeObfuscatedTicketAge(
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot,
        long nowTicks)
    {
        long elapsedTicks = nowTicks > detachedResumptionTicketSnapshot.CapturedAtTicks
            ? nowTicks - detachedResumptionTicketSnapshot.CapturedAtTicks
            : 0;
        ulong ticketAgeMilliseconds = elapsedTicks <= 0
            ? 0
            : (unchecked((ulong)elapsedTicks) * 1_000UL) / (ulong)Stopwatch.Frequency;
        uint ticketAgeMilliseconds32 = unchecked((uint)ticketAgeMilliseconds);
        return unchecked(ticketAgeMilliseconds32 + detachedResumptionTicketSnapshot.TicketAgeAdd);
    }

    private enum ClientHelloApplicationProtocolOfferState
    {
        Missing = 0,
        Present = 1,
        Invalid = 2,
    }
}
