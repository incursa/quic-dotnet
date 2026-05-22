namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0240")]
public sealed class REQ_QUIC_RFC9000_0240
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0240">An endpoint MAY change the connection ID it uses for a peer to another available one at any time during the connection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0240")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewConnectionIdFrame_CanSwitchOutboundPeerDestinationConnectionIdDuringPathSelection()
    {
        QuicConnectionPeerConnectionIdState state = new();
        QuicConnectionPathIdentity originalPath = new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.20",
            RemotePort: 443,
            LocalPort: 5000);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.10",
            LocalAddress: "198.51.100.21",
            RemotePort: 443,
            LocalPort: 5001);
        byte[] originalDestinationConnectionId = [0x41, 0x42, 0x43, 0x44];
        byte[] switchedDestinationConnectionId = [0x51, 0x52, 0x53, 0x54];

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                1UL,
                0UL,
                switchedDestinationConnectionId,
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x90)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 3UL,
            originalDestinationConnectionId,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(originalDestinationConnectionId, state.CurrentDestinationConnectionId.ToArray());

        Assert.True(state.TryUseDestinationConnectionIdOnPath(
            originalPath,
            activeConnectionIdLimit: 3UL,
            retireInactivePathConnectionIds: false,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(originalDestinationConnectionId, state.CurrentDestinationConnectionId.ToArray());

        Assert.True(state.TryUseDestinationConnectionIdOnPath(
            migratedPath,
            activeConnectionIdLimit: 3UL,
            retireInactivePathConnectionIds: false,
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(switchedDestinationConnectionId, state.CurrentDestinationConnectionId.ToArray());
    }
}
