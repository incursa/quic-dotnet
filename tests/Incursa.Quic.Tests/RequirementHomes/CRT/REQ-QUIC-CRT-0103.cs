namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0103")]
public sealed class REQ_QUIC_CRT_0103
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TlsBridgeStateTracksTransportFactsAcrossTheHandshakeLifecycle()
    {
        QuicTransportTlsBridgeState bridge = new();
        QuicTransportParameters localParameters = new();
        QuicTransportParameters peerParameters = new();

        Assert.False(bridge.HasAnyAvailableKeys);
        Assert.False(bridge.IsTerminal);
        Assert.True(bridge.TryCommitLocalTransportParameters(localParameters));
        Assert.True(bridge.TryAuthenticatePeerTransportParameters(peerParameters));
        Assert.True(bridge.TryMarkInitialKeysAvailable());
        Assert.True(bridge.TryMarkHandshakeKeysAvailable());
        Assert.True(bridge.TryMarkApplicationKeysAvailable());
        Assert.True(bridge.TryConfirmHandshake());
        Assert.True(bridge.TryInstallKeyUpdate());
        Assert.True(bridge.TryDiscardOldKeys());

        Assert.Same(localParameters, bridge.LocalTransportParameters);
        Assert.Same(peerParameters, bridge.PeerTransportParameters);
        Assert.True(bridge.PeerTransportParametersAuthenticated);
        Assert.True(bridge.InitialKeysAvailable);
        Assert.True(bridge.HandshakeKeysAvailable);
        Assert.True(bridge.ApplicationKeysAvailable);
        Assert.True(bridge.HandshakeConfirmed);
        Assert.True(bridge.KeyUpdateInstalled);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.Null(bridge.FatalAlertCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FatalAlertsDiscardKeyAvailabilityAndMarkTheBridgeTerminal()
    {
        QuicTransportTlsBridgeState bridge = new();

        Assert.True(bridge.TryMarkInitialKeysAvailable());
        Assert.True(bridge.TryMarkHandshakeKeysAvailable());
        Assert.True(bridge.TryMarkApplicationKeysAvailable());
        Assert.True(bridge.TryRecordFatalAlert(QuicTransportErrorCode.ProtocolViolation, "fatal handshake failure"));

        Assert.True(bridge.IsTerminal);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, bridge.FatalAlertCode);
        Assert.Equal("fatal handshake failure", bridge.FatalAlertDescription);
        Assert.False(bridge.HasAnyAvailableKeys);
        Assert.True(bridge.OldKeysDiscarded);
    }
}
