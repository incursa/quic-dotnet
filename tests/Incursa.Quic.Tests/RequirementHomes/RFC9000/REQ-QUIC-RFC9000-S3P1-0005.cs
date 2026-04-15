namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0005">The sending part of a bidirectional stream initiated by a peer MUST start in the Ready state when the receiving part is created.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P1-0005")]
public sealed class REQ_QUIC_RFC9000_S3P1_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_StartsPeerInitiatedBidirectionalSendersInReady()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerBidirectionalStreamLimit: 1);
        byte[] encodedFrame = QuicStreamTestData.BuildStreamFrame(0x0A, 1, [0x11]);

        Assert.True(QuicStreamParser.TryParseStreamFrame(encodedFrame, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(1UL, snapshot.UniqueBytesReceived);
        Assert.Equal(1UL, snapshot.AccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_DoesNotStartPeerInitiatedUnidirectionalSendersInReady()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerUnidirectionalStreamLimit: 1);
        byte[] encodedFrame = QuicStreamTestData.BuildStreamFrame(0x0A, 3, [0x11]);

        Assert.True(QuicStreamParser.TryParseStreamFrame(encodedFrame, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(3, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.None, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);

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
    }
}
