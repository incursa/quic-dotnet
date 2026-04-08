namespace Incursa.Quic;

/// <summary>
/// Tracks the transport-facing facts that a TLS bridge would publish into the connection runtime.
/// </summary>
internal sealed class QuicTransportTlsBridgeState
{
    public QuicTransportParameters? LocalTransportParameters { get; private set; }

    public QuicTransportParameters? PeerTransportParameters { get; private set; }

    public bool PeerTransportParametersAuthenticated { get; private set; }

    public bool InitialKeysAvailable { get; private set; }

    public bool HandshakeKeysAvailable { get; private set; }

    public bool ApplicationKeysAvailable { get; private set; }

    public bool HandshakeConfirmed { get; private set; }

    public bool KeyUpdateInstalled { get; private set; }

    public bool OldKeysDiscarded { get; private set; }

    public QuicTransportErrorCode? FatalAlertCode { get; private set; }

    public string? FatalAlertDescription { get; private set; }

    public bool HasAnyAvailableKeys => InitialKeysAvailable || HandshakeKeysAvailable || ApplicationKeysAvailable;

    public bool IsTerminal => FatalAlertCode.HasValue;

    public bool TryCommitLocalTransportParameters(QuicTransportParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (IsTerminal || ReferenceEquals(LocalTransportParameters, parameters))
        {
            return false;
        }

        LocalTransportParameters = parameters;
        return true;
    }

    public bool TryAuthenticatePeerTransportParameters(QuicTransportParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (IsTerminal || (PeerTransportParametersAuthenticated && ReferenceEquals(PeerTransportParameters, parameters)))
        {
            return false;
        }

        PeerTransportParameters = parameters;
        PeerTransportParametersAuthenticated = true;
        return true;
    }

    public bool TryMarkInitialKeysAvailable()
    {
        if (IsTerminal || InitialKeysAvailable)
        {
            return false;
        }

        InitialKeysAvailable = true;
        return true;
    }

    public bool TryMarkHandshakeKeysAvailable()
    {
        if (IsTerminal || HandshakeKeysAvailable)
        {
            return false;
        }

        HandshakeKeysAvailable = true;
        return true;
    }

    public bool TryMarkApplicationKeysAvailable()
    {
        if (IsTerminal || ApplicationKeysAvailable)
        {
            return false;
        }

        ApplicationKeysAvailable = true;
        return true;
    }

    public bool TryConfirmHandshake()
    {
        if (IsTerminal || HandshakeConfirmed)
        {
            return false;
        }

        HandshakeConfirmed = true;
        return true;
    }

    public bool TryInstallKeyUpdate()
    {
        if (IsTerminal || !ApplicationKeysAvailable || KeyUpdateInstalled)
        {
            return false;
        }

        KeyUpdateInstalled = true;
        return true;
    }

    public bool TryDiscardOldKeys()
    {
        if (IsTerminal || OldKeysDiscarded)
        {
            return false;
        }

        OldKeysDiscarded = true;
        return true;
    }

    public bool TryRecordFatalAlert(QuicTransportErrorCode alertCode, string? description = null)
    {
        if (FatalAlertCode.HasValue && FatalAlertCode.Value == alertCode && FatalAlertDescription == description)
        {
            return false;
        }

        FatalAlertCode = alertCode;
        FatalAlertDescription = description;
        InitialKeysAvailable = false;
        HandshakeKeysAvailable = false;
        ApplicationKeysAvailable = false;
        KeyUpdateInstalled = false;
        OldKeysDiscarded = true;
        return true;
    }
}
