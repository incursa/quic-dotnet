namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P1-0002")]
public sealed class REQ_QUIC_RFC9000_S3P1_0002
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0002">An implementation MAY buffer stream data in the Ready state in preparation for sending.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_BuffersDataInReadyState()
    {
        QuicConnectionStreamState state = CreateState(localBidirectionalSendLimit: 8, connectionSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _));
        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.None, snapshot.ReceiveState);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
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
