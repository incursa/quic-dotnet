namespace Incursa.Quic;

/// <summary>
/// The endpoint role presented to the TLS bridge.
/// </summary>
internal enum QuicTlsRole
{
    Client = 0,
    Server = 1,
}

/// <summary>
/// QUIC encryption epochs surfaced to the transport.
/// </summary>
internal enum QuicTlsEncryptionLevel
{
    Initial = 0,
    Handshake = 1,
    OneRtt = 2,
}

/// <summary>
/// TLS 1.3 handshake message types relevant to the transcript owner.
/// </summary>
internal enum QuicTlsHandshakeMessageType : byte
{
    ClientHello = 0x01,
    ServerHello = 0x02,
    NewSessionTicket = 0x04,
    EncryptedExtensions = 0x08,
    Certificate = 0x0B,
    CertificateRequest = 0x0D,
    CertificateVerify = 0x0F,
    Finished = 0x14,
}

/// <summary>
/// TLS 1.3 cipher suites supported by the transcript owner.
/// </summary>
internal enum QuicTlsCipherSuite : ushort
{
    TlsAes128GcmSha256 = 0x1301,
    TlsAes256GcmSha384 = 0x1302,
    TlsChacha20Poly1305Sha256 = 0x1303,
}

/// <summary>
/// TLS 1.3 signature schemes supported by the client-role certificate proof slice.
/// </summary>
internal enum QuicTlsSignatureScheme : ushort
{
    EcdsaSecp256r1Sha256 = 0x0403,
}

/// <summary>
/// TLS 1.3 named groups supported by the managed key schedule slice.
/// </summary>
internal enum QuicTlsNamedGroup : ushort
{
    Secp256r1 = 0x0017,
}

/// <summary>
/// TLS transcript hash algorithms implied by the supported cipher suites.
/// </summary>
internal enum QuicTlsTranscriptHashAlgorithm
{
    Sha256 = 0,
    Sha384 = 1,
}

/// <summary>
/// Handshake transcript progress owned behind the transport-facing TLS bridge.
/// </summary>
internal enum QuicTlsTranscriptPhase
{
    AwaitingPeerHandshakeMessage = 0,
    PeerTransportParametersStaged = 1,
    Completed = 2,
    Failed = 3,
}

/// <summary>
/// TLS-to-transport state update kinds.
/// </summary>
internal enum QuicTlsUpdateKind
{
    LocalTransportParametersReady = 0,
    PeerTransportParametersCommitted = 1,
    KeysAvailable = 2,
    PeerHandshakeTranscriptCompleted = 3,
    KeyUpdateInstalled = 4,
    KeysDiscarded = 5,
    FatalAlert = 6,
    ProhibitedKeyUpdateViolation = 7,
    CryptoDataAvailable = 8,
    PacketProtectionMaterialAvailable = 9,
    TranscriptProgressed = 10,
    PeerFinishedVerified = 11,
    HandshakeOpenPacketProtectionMaterialAvailable = 12,
    HandshakeProtectPacketProtectionMaterialAvailable = 13,
    PeerCertificateVerifyVerified = 14,
    PeerCertificatePolicyAccepted = 15,
    OneRttOpenPacketProtectionMaterialAvailable = 16,
    OneRttProtectPacketProtectionMaterialAvailable = 17,
    PostHandshakeTicketAvailable = 18,
}

/// <summary>
/// A transport-facing TLS state update.
/// </summary>
internal readonly record struct QuicTlsStateUpdate(
    QuicTlsUpdateKind Kind,
    QuicTlsEncryptionLevel? EncryptionLevel = null,
    QuicTransportParameters? TransportParameters = null,
    QuicTlsHandshakeMessageType? HandshakeMessageType = null,
    uint? HandshakeMessageLength = null,
    QuicTlsCipherSuite? SelectedCipherSuite = null,
    QuicTlsTranscriptHashAlgorithm? TranscriptHashAlgorithm = null,
    uint? KeyPhase = null,
    ushort? AlertDescription = null,
    ulong? CryptoDataOffset = null,
    ReadOnlyMemory<byte> CryptoData = default,
    QuicTlsPacketProtectionMaterial? PacketProtectionMaterial = null,
    QuicTlsTranscriptPhase? TranscriptPhase = null,
    ReadOnlyMemory<byte> TicketBytes = default);

/// <summary>
/// A transport-facing bridge to a concrete TLS implementation.
/// </summary>
internal interface IQuicTlsTransportBridge
{
    /// <summary>
    /// Gets the endpoint role owned by the bridge.
    /// </summary>
    QuicTlsRole Role { get; }

    /// <summary>
    /// Starts a handshake and returns any initial state updates.
    /// </summary>
    /// <param name="localTransportParameters">The local transport parameters to advertise.</param>
    /// <returns>The state updates produced by TLS.</returns>
    IReadOnlyList<QuicTlsStateUpdate> StartHandshake(QuicTransportParameters localTransportParameters);

    /// <summary>
    /// Processes CRYPTO payload received at one encryption level.
    /// </summary>
    /// <param name="encryptionLevel">The encryption level for the CRYPTO payload.</param>
    /// <param name="cryptoFramePayload">The CRYPTO frame payload bytes.</param>
    /// <returns>The state updates produced by TLS.</returns>
    IReadOnlyList<QuicTlsStateUpdate> ProcessCryptoFrame(
        QuicTlsEncryptionLevel encryptionLevel,
        ReadOnlyMemory<byte> cryptoFramePayload);

    /// <summary>
    /// Commits staged peer transport parameters into the bridge.
    /// </summary>
    /// <param name="peerTransportParameters">The staged peer transport parameters to commit.</param>
    /// <returns>The state updates produced by TLS.</returns>
    IReadOnlyList<QuicTlsStateUpdate> CommitPeerTransportParameters(
        QuicTransportParameters peerTransportParameters);
}
