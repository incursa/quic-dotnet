namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0185")]
public sealed class REQ_QUIC_RFC9000_0185
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0185")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveResetStreamFrame_DoesNotResetTheOppositeSendDirection()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            connectionSendLimit: 32,
            peerBidirectionalReceiveLimit: 8,
            peerBidirectionalSendLimit: 8);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 0),
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.NotEqual(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.NotEqual(QuicStreamSendState.ResetRecvd, snapshot.SendState);

        Assert.True(state.TryReserveSendCapacity(
            1,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);
    }
}
