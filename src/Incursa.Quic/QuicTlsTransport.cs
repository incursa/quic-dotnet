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
/// TLS-to-transport state update kinds.
/// </summary>
internal enum QuicTlsUpdateKind
{
    LocalTransportParametersReady = 0,
    PeerTransportParametersAuthenticated = 1,
    KeysAvailable = 2,
    HandshakeConfirmed = 3,
    KeyUpdateInstalled = 4,
    KeysDiscarded = 5,
    FatalAlert = 6,
    ProhibitedKeyUpdateViolation = 7,
    CryptoDataAvailable = 8,
    PacketProtectionMaterialAvailable = 9,
}

/// <summary>
/// A transport-facing TLS state update.
/// </summary>
internal readonly record struct QuicTlsStateUpdate(
    QuicTlsUpdateKind Kind,
    QuicTlsEncryptionLevel? EncryptionLevel = null,
    QuicTransportParameters? TransportParameters = null,
    uint? KeyPhase = null,
    ushort? AlertDescription = null,
    ulong? CryptoDataOffset = null,
    ReadOnlyMemory<byte> CryptoData = default,
    QuicTlsPacketProtectionMaterial? PacketProtectionMaterial = null);

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
    /// Commits authenticated peer transport parameters into the bridge.
    /// </summary>
    /// <param name="peerTransportParameters">The authenticated peer transport parameters.</param>
    /// <returns>The state updates produced by TLS.</returns>
    IReadOnlyList<QuicTlsStateUpdate> CommitPeerTransportParameters(
        QuicTransportParameters peerTransportParameters);
}
