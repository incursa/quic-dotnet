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
}

/// <summary>
/// A transport-facing TLS state update.
/// </summary>
internal readonly record struct QuicTlsStateUpdate(
    QuicTlsUpdateKind Kind,
    QuicTlsEncryptionLevel? EncryptionLevel = null,
    QuicTransportParameters? TransportParameters = null,
    uint? KeyPhase = null,
    ushort? AlertDescription = null);

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

/// <summary>
/// Mutable connection-owned TLS transport state derived from <see cref="QuicTlsStateUpdate"/> values.
/// </summary>
internal sealed class QuicTlsTransportState
{
    /// <summary>
    /// Gets the local transport parameters that are ready to send.
    /// </summary>
    public QuicTransportParameters? LocalTransportParameters { get; private set; }

    /// <summary>
    /// Gets the authenticated peer transport parameters.
    /// </summary>
    public QuicTransportParameters? PeerTransportParameters { get; private set; }

    /// <summary>
    /// Gets whether Initial keys are available.
    /// </summary>
    public bool InitialKeysAvailable { get; private set; }

    /// <summary>
    /// Gets whether Handshake keys are available.
    /// </summary>
    public bool HandshakeKeysAvailable { get; private set; }

    /// <summary>
    /// Gets whether 1-RTT keys are available.
    /// </summary>
    public bool OneRttKeysAvailable { get; private set; }

    /// <summary>
    /// Gets whether Initial keys have been discarded.
    /// </summary>
    public bool InitialKeysDiscarded { get; private set; }

    /// <summary>
    /// Gets whether Handshake keys have been discarded.
    /// </summary>
    public bool HandshakeKeysDiscarded { get; private set; }

    /// <summary>
    /// Gets whether 1-RTT keys have been discarded.
    /// </summary>
    public bool OneRttKeysDiscarded { get; private set; }

    /// <summary>
    /// Gets whether the handshake is confirmed.
    /// </summary>
    public bool HandshakeConfirmed { get; private set; }

    /// <summary>
    /// Gets the current 1-RTT key phase.
    /// </summary>
    public uint CurrentOneRttKeyPhase { get; private set; }

    /// <summary>
    /// Gets the fatal alert description, when one has been reported.
    /// </summary>
    public ushort? FatalAlertDescription { get; private set; }

    /// <summary>
    /// Applies one TLS state update.
    /// </summary>
    /// <param name="update">The update to apply.</param>
    /// <returns><see langword="true"/> when the update was valid for the contract.</returns>
    public bool TryApply(QuicTlsStateUpdate update)
    {
        switch (update.Kind)
        {
            case QuicTlsUpdateKind.LocalTransportParametersReady:
                if (update.TransportParameters is null)
                {
                    return false;
                }

                LocalTransportParameters = update.TransportParameters;
                return true;

            case QuicTlsUpdateKind.PeerTransportParametersAuthenticated:
                if (update.TransportParameters is null)
                {
                    return false;
                }

                PeerTransportParameters = update.TransportParameters;
                return true;

            case QuicTlsUpdateKind.KeysAvailable:
                if (!update.EncryptionLevel.HasValue)
                {
                    return false;
                }

                SetKeysAvailable(update.EncryptionLevel.Value, true);
                SetKeysDiscarded(update.EncryptionLevel.Value, false);
                return true;

            case QuicTlsUpdateKind.HandshakeConfirmed:
                HandshakeConfirmed = true;
                return true;

            case QuicTlsUpdateKind.KeyUpdateInstalled:
                if (!update.KeyPhase.HasValue)
                {
                    return false;
                }

                CurrentOneRttKeyPhase = update.KeyPhase.Value;
                OneRttKeysAvailable = true;
                return true;

            case QuicTlsUpdateKind.KeysDiscarded:
                if (!update.EncryptionLevel.HasValue)
                {
                    return false;
                }

                SetKeysDiscarded(update.EncryptionLevel.Value, true);
                return true;

            case QuicTlsUpdateKind.FatalAlert:
                if (!update.AlertDescription.HasValue)
                {
                    return false;
                }

                FatalAlertDescription = update.AlertDescription.Value;
                return true;

            default:
                return false;
        }
    }

    private void SetKeysAvailable(QuicTlsEncryptionLevel encryptionLevel, bool available)
    {
        switch (encryptionLevel)
        {
            case QuicTlsEncryptionLevel.Initial:
                InitialKeysAvailable = available;
                break;
            case QuicTlsEncryptionLevel.Handshake:
                HandshakeKeysAvailable = available;
                break;
            case QuicTlsEncryptionLevel.OneRtt:
                OneRttKeysAvailable = available;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(encryptionLevel));
        }
    }

    private void SetKeysDiscarded(QuicTlsEncryptionLevel encryptionLevel, bool discarded)
    {
        switch (encryptionLevel)
        {
            case QuicTlsEncryptionLevel.Initial:
                InitialKeysDiscarded = discarded;
                break;
            case QuicTlsEncryptionLevel.Handshake:
                HandshakeKeysDiscarded = discarded;
                break;
            case QuicTlsEncryptionLevel.OneRtt:
                OneRttKeysDiscarded = discarded;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(encryptionLevel));
        }
    }
}
