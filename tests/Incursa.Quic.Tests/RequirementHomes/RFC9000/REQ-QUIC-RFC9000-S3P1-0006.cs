namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0006">In the Send state, an endpoint MUST transmit and retransmit as necessary stream data in STREAM frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P1-0006")]
public sealed class REQ_QUIC_RFC9000_S3P1_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_TransitionsPeerInitiatedBidirectionalSendersIntoSendAndRetransmits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerBidirectionalStreamLimit: 1);
        byte[] encodedFrame = QuicStreamTestData.BuildStreamFrame(0x0A, 1, [0x11, 0x22]);

        Assert.True(QuicStreamParser.TryParseStreamFrame(encodedFrame, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReserveSendCapacity(
            1,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamSendState.Send, sendSnapshot.SendState);
        Assert.Equal(2UL, sendSnapshot.UniqueBytesSent);

        Assert.True(state.TryReserveSendCapacity(
            1,
            offset: 0,
            length: 2,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot retransmitSnapshot));
        Assert.Equal(QuicStreamSendState.Send, retransmitSnapshot.SendState);
        Assert.Equal(2UL, retransmitSnapshot.UniqueBytesSent);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_RejectsPeerInitiatedUnidirectionalStreamsWithoutASendPart()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerUnidirectionalStreamLimit: 1);
        byte[] encodedFrame = QuicStreamTestData.BuildStreamFrame(0x0A, 3, [0x11]);

        Assert.True(QuicStreamParser.TryParseStreamFrame(encodedFrame, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReserveSendCapacity(
            3,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);

        Assert.True(state.TryGetStreamSnapshot(3, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.None, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }
}
