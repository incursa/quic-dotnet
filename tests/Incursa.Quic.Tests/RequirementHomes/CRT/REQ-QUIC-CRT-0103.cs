namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0103")]
public sealed class REQ_QUIC_CRT_0103
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TlsBridgeStateSnapshotsTransportParametersAndTracksKeyLifecycleOutputs()
    {
        QuicTransportParameters localParameters = new()
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };

        QuicTransportParameters peerSeedParameters = new()
        {
            MaxIdleTimeout = 30,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0xAA, 0xBB, 0xCC],
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                IPv6Port = 8443,
                ConnectionId = [0x10, 0x11],
                StatelessResetToken = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F],
            },
            ActiveConnectionIdLimit = 4,
        };

        Span<byte> encodedPeerParameters = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            peerSeedParameters,
            QuicTransportParameterRole.Server,
            encodedPeerParameters,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encodedPeerParameters[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedPeerParameters));

        QuicTransportTlsBridgeState bridge = new();

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: localParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
            TransportParameters: parsedPeerParameters)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Initial)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.HandshakeConfirmed)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeyUpdateInstalled,
            KeyPhase: 2)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysDiscarded,
            QuicTlsEncryptionLevel.Initial)));

        localParameters.InitialSourceConnectionId![0] = 0xFF;
        parsedPeerParameters.InitialSourceConnectionId![0] = 0xEE;
        parsedPeerParameters.PreferredAddress!.ConnectionId[0] = 0x99;
        parsedPeerParameters.PreferredAddress.StatelessResetToken[0] = 0x98;

        Assert.NotSame(localParameters, bridge.LocalTransportParameters);
        Assert.NotSame(parsedPeerParameters, bridge.PeerTransportParameters);
        Assert.Equal(15UL, bridge.LocalTransportParameters!.MaxIdleTimeout);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, bridge.LocalTransportParameters.InitialSourceConnectionId);
        Assert.Equal(30UL, bridge.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(bridge.PeerTransportParametersAuthenticated);
        Assert.False(bridge.InitialKeysAvailable);
        Assert.True(bridge.HandshakeKeysAvailable);
        Assert.True(bridge.OneRttKeysAvailable);
        Assert.True(bridge.HandshakeConfirmed);
        Assert.True(bridge.KeyUpdateInstalled);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.Equal(2U, bridge.CurrentOneRttKeyPhase);
        Assert.True(bridge.HasAnyAvailableKeys);
        Assert.False(bridge.IsTerminal);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, bridge.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(new byte[] { 0x10, 0x11 }, bridge.PeerTransportParameters.PreferredAddress!.ConnectionId);
        Assert.Equal(new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F }, bridge.PeerTransportParameters.PreferredAddress.StatelessResetToken);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProhibitedKeyUpdatesMarkTheBridgeTerminal()
    {
        QuicTransportTlsBridgeState bridge = new();

        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        Assert.True(bridge.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation)));

        Assert.True(bridge.IsTerminal);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, bridge.FatalAlertCode);
        Assert.Equal("TLS KeyUpdate was prohibited.", bridge.FatalAlertDescription);
        Assert.False(bridge.HasAnyAvailableKeys);
        Assert.True(bridge.OldKeysDiscarded);
        Assert.False(bridge.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
    }
}
