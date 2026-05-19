namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0003")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0003
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0003">An endpoint MUST maintain a set of connection IDs received from its peer for use when sending packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcceptNewConnectionId_MaintainsThePeerIssuedConnectionIdSetForOutboundSelection()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                1UL,
                0UL,
                [0x10, 0x11, 0x12],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x20)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 3UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
        Assert.Equal(0UL, state.CurrentDestinationConnectionIdSequence);
        Assert.Equal([0x01, 0x02, 0x03], state.CurrentDestinationConnectionId.ToArray());

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                2UL,
                1UL,
                [0x20, 0x21, 0x22],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 3UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL], retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
        Assert.Equal(2UL, state.CurrentDestinationConnectionIdSequence);
        Assert.Equal([0x20, 0x21, 0x22], state.CurrentDestinationConnectionId.ToArray());
    }
}
