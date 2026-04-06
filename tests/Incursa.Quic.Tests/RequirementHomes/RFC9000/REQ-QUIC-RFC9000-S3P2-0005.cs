namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P2-0005")]
public sealed class REQ_QUIC_RFC9000_S3P2_0005
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0005">The initial state for the receiving part of a stream MUST be Recv.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_InitializesTheReceivingPartInRecv()
    {
        QuicConnectionStreamState state = CreateState(connectionReceiveLimit: 16, peerBidirectionalReceiveLimit: 8);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 5, [0x10, 0x11], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }

    private static QuicConnectionStreamState CreateState(
        ulong connectionReceiveLimit = 64,
        ulong connectionSendLimit = 64,
        ulong incomingBidirectionalStreamLimit = 4,
        ulong incomingUnidirectionalStreamLimit = 4,
        ulong peerBidirectionalStreamLimit = 4,
        ulong peerUnidirectionalStreamLimit = 4,
        ulong localBidirectionalReceiveLimit = 8,
        ulong peerBidirectionalReceiveLimit = 8,
        ulong peerUnidirectionalReceiveLimit = 8,
        ulong localBidirectionalSendLimit = 8,
        ulong localUnidirectionalSendLimit = 8,
        ulong peerBidirectionalSendLimit = 8)
    {
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
            IsServer: false,
            InitialConnectionReceiveLimit: connectionReceiveLimit,
            InitialConnectionSendLimit: connectionSendLimit,
            InitialIncomingBidirectionalStreamLimit: incomingBidirectionalStreamLimit,
            InitialIncomingUnidirectionalStreamLimit: incomingUnidirectionalStreamLimit,
            InitialPeerBidirectionalStreamLimit: peerBidirectionalStreamLimit,
            InitialPeerUnidirectionalStreamLimit: peerUnidirectionalStreamLimit,
            InitialLocalBidirectionalReceiveLimit: localBidirectionalReceiveLimit,
            InitialPeerBidirectionalReceiveLimit: peerBidirectionalReceiveLimit,
            InitialPeerUnidirectionalReceiveLimit: peerUnidirectionalReceiveLimit,
            InitialLocalBidirectionalSendLimit: localBidirectionalSendLimit,
            InitialLocalUnidirectionalSendLimit: localUnidirectionalSendLimit,
            InitialPeerBidirectionalSendLimit: peerBidirectionalSendLimit));
    }
}
