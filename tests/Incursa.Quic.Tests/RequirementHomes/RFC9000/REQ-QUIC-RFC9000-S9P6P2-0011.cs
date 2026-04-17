namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P2-0011")]
public sealed class REQ_QUIC_RFC9000_S9P6P2_0011
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CurrentConnectionSnapshotsKeepPreferredAddressStateIsolatedFromTheSourceTransportParameters()
    {
        byte[] expectedInitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] initialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] expectedPreferredIpv4Address = [198, 51, 100, 110];
        byte[] preferredIpv4Address = [198, 51, 100, 110];
        byte[] expectedPreferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x6E];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x6E];
        byte[] expectedPreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] preferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] expectedStatelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
        byte[] preferredStatelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters(
            initialSourceConnectionId,
            preferredIpv4Address,
            preferredIpv4Port: 9443,
            preferredIpv6Address,
            preferredIpv6Port: 9553,
            preferredConnectionId,
            preferredStatelessResetToken);

        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(runtime, peerTransportParameters);

        Assert.NotNull(runtime.TlsState.PeerTransportParameters);
        Assert.NotNull(runtime.TlsState.PeerTransportParameters!.PreferredAddress);
        QuicTransportParameters snapshot = Assert.IsType<QuicTransportParameters>(runtime.TlsState.PeerTransportParametersSnapshot);
        Assert.NotNull(snapshot.PreferredAddress);

        Assert.NotSame(peerTransportParameters.PreferredAddress, runtime.TlsState.PeerTransportParameters.PreferredAddress);
        Assert.NotSame(runtime.TlsState.PeerTransportParameters.PreferredAddress, snapshot.PreferredAddress);

        byte[] sourceInitialSourceConnectionId = peerTransportParameters.InitialSourceConnectionId!;
        QuicPreferredAddress sourcePreferredAddress = peerTransportParameters.PreferredAddress!;

        sourceInitialSourceConnectionId[0] = 0xEE;
        sourcePreferredAddress.IPv4Address[0] = 0xDD;
        sourcePreferredAddress.IPv6Address[0] = 0xCC;
        sourcePreferredAddress.ConnectionId[0] = 0xBB;
        sourcePreferredAddress.StatelessResetToken[0] = 0xAA;

        Assert.Equal(expectedInitialSourceConnectionId, runtime.TlsState.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(expectedPreferredIpv4Address, runtime.TlsState.PeerTransportParameters.PreferredAddress!.IPv4Address);
        Assert.Equal(expectedPreferredIpv6Address, runtime.TlsState.PeerTransportParameters.PreferredAddress.IPv6Address);
        Assert.Equal(expectedPreferredConnectionId, runtime.TlsState.PeerTransportParameters.PreferredAddress.ConnectionId);
        Assert.Equal(expectedStatelessResetToken, runtime.TlsState.PeerTransportParameters.PreferredAddress.StatelessResetToken);
        Assert.Equal(expectedInitialSourceConnectionId, snapshot.InitialSourceConnectionId);
        Assert.Equal(expectedPreferredIpv4Address, snapshot.PreferredAddress!.IPv4Address);
        Assert.Equal(expectedPreferredIpv6Address, snapshot.PreferredAddress.IPv6Address);
        Assert.Equal(expectedPreferredConnectionId, snapshot.PreferredAddress.ConnectionId);
        Assert.Equal(expectedStatelessResetToken, snapshot.PreferredAddress.StatelessResetToken);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6P2-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SeparateConnectionsKeepDistinctPreferredAddressSnapshots()
    {
        byte[] expectedInitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] initialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] expectedPreferredIpv4Address = [198, 51, 100, 111];
        byte[] preferredIpv4Address = [198, 51, 100, 111];
        byte[] expectedPreferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x6F];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x6F];
        byte[] expectedPreferredConnectionId = [0x40, 0x41, 0x42, 0x43];
        byte[] preferredConnectionId = [0x40, 0x41, 0x42, 0x43];
        byte[] expectedStatelessResetToken = [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F];
        byte[] preferredStatelessResetToken = [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F];

        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters(
            initialSourceConnectionId,
            preferredIpv4Address,
            preferredIpv4Port: 9444,
            preferredIpv6Address,
            preferredIpv6Port: 9554,
            preferredConnectionId,
            preferredStatelessResetToken);

        QuicConnectionRuntime firstRuntime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        QuicConnectionRuntime secondRuntime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(firstRuntime, peerTransportParameters);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParameters(secondRuntime, peerTransportParameters);

        Assert.NotNull(firstRuntime.TlsState.PeerTransportParameters);
        Assert.NotNull(secondRuntime.TlsState.PeerTransportParameters);
        Assert.NotNull(firstRuntime.TlsState.PeerTransportParameters!.PreferredAddress);
        Assert.NotNull(secondRuntime.TlsState.PeerTransportParameters!.PreferredAddress);

        QuicTransportParameters firstSnapshot = Assert.IsType<QuicTransportParameters>(firstRuntime.TlsState.PeerTransportParametersSnapshot);
        QuicTransportParameters secondSnapshot = Assert.IsType<QuicTransportParameters>(secondRuntime.TlsState.PeerTransportParametersSnapshot);
        Assert.NotNull(firstSnapshot.PreferredAddress);
        Assert.NotNull(secondSnapshot.PreferredAddress);

        Assert.NotSame(firstRuntime.TlsState.PeerTransportParameters.PreferredAddress, secondRuntime.TlsState.PeerTransportParameters.PreferredAddress);
        Assert.NotSame(firstSnapshot.PreferredAddress, secondSnapshot.PreferredAddress);

        QuicTransportParameters firstCommittedTransportParameters = firstRuntime.TlsState.PeerTransportParameters!;
        QuicPreferredAddress firstCommittedPreferredAddress = firstCommittedTransportParameters.PreferredAddress!;
        byte[] firstCommittedInitialSourceConnectionId = firstCommittedTransportParameters.InitialSourceConnectionId!;

        firstCommittedInitialSourceConnectionId[0] = 0xA5;
        firstCommittedPreferredAddress.IPv4Address[0] = 0xA1;
        firstCommittedPreferredAddress.IPv6Address[0] = 0xA2;
        firstCommittedPreferredAddress.ConnectionId[0] = 0xA3;
        firstCommittedPreferredAddress.StatelessResetToken[0] = 0xA4;

        QuicTransportParameters secondCommittedTransportParameters = secondRuntime.TlsState.PeerTransportParameters!;
        QuicPreferredAddress secondCommittedPreferredAddress = secondCommittedTransportParameters.PreferredAddress!;

        Assert.Equal(expectedInitialSourceConnectionId, secondCommittedTransportParameters.InitialSourceConnectionId);
        Assert.Equal(expectedPreferredIpv4Address, secondCommittedPreferredAddress.IPv4Address);
        Assert.Equal(expectedPreferredIpv6Address, secondCommittedPreferredAddress.IPv6Address);
        Assert.Equal(expectedPreferredConnectionId, secondCommittedPreferredAddress.ConnectionId);
        Assert.Equal(expectedStatelessResetToken, secondCommittedPreferredAddress.StatelessResetToken);
        Assert.Equal(expectedInitialSourceConnectionId, firstSnapshot.InitialSourceConnectionId);
        Assert.Equal(expectedPreferredIpv4Address, firstSnapshot.PreferredAddress!.IPv4Address);
        Assert.Equal(expectedPreferredIpv6Address, firstSnapshot.PreferredAddress.IPv6Address);
        Assert.Equal(expectedPreferredConnectionId, firstSnapshot.PreferredAddress.ConnectionId);
        Assert.Equal(expectedStatelessResetToken, firstSnapshot.PreferredAddress.StatelessResetToken);
        Assert.Equal(expectedInitialSourceConnectionId, secondSnapshot.InitialSourceConnectionId);
        Assert.Equal(expectedPreferredIpv4Address, secondSnapshot.PreferredAddress!.IPv4Address);
        Assert.Equal(expectedPreferredIpv6Address, secondSnapshot.PreferredAddress.IPv6Address);
        Assert.Equal(expectedPreferredConnectionId, secondSnapshot.PreferredAddress.ConnectionId);
        Assert.Equal(expectedStatelessResetToken, secondSnapshot.PreferredAddress.StatelessResetToken);
    }

    private static QuicTransportParameters CreatePeerTransportParameters(
        byte[] initialSourceConnectionId,
        byte[] preferredIpv4Address,
        ushort preferredIpv4Port,
        byte[] preferredIpv6Address,
        ushort preferredIpv6Port,
        byte[] preferredConnectionId,
        byte[] preferredStatelessResetToken)
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = preferredIpv4Port,
                IPv6Address = preferredIpv6Address,
                IPv6Port = preferredIpv6Port,
                ConnectionId = preferredConnectionId,
                StatelessResetToken = preferredStatelessResetToken,
            },
        };
    }
}
