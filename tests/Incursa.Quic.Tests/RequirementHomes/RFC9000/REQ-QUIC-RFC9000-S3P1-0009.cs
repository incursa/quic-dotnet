namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P1-0009")]
public sealed class REQ_QUIC_RFC9000_S3P1_0009
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0009">After the application indicates that all stream data has been sent and a STREAM frame containing the FIN bit is sent, the sending part of the stream MUST enter the Data Sent state.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_EntersDataSentAfterFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerUnidirectionalStreamLimit: 1,
            localUnidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot readySnapshot));
        Assert.Equal(QuicStreamSendState.Ready, readySnapshot.SendState);

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

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamSendState.Send, sendSnapshot.SendState);
        Assert.Equal(2UL, sendSnapshot.UniqueBytesSent);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 2,
            length: 1,
            fin: true,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
        Assert.True(dataSentSnapshot.HasFinalSize);
        Assert.Equal(3UL, dataSentSnapshot.FinalSize);
        Assert.Equal(3UL, dataSentSnapshot.UniqueBytesSent);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_LeavesStreamInSendStateWithoutFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerUnidirectionalStreamLimit: 1,
            localUnidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamSendState.Send, sendSnapshot.SendState);
        Assert.False(sendSnapshot.HasFinalSize);
        Assert.Equal(1UL, sendSnapshot.UniqueBytesSent);
        Assert.Equal(1UL, state.ConnectionUniqueBytesSent);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0009")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReserveSendCapacity_EntersDataSentOnZeroLengthFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 0,
            peerUnidirectionalStreamLimit: 1,
            localUnidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 0,
            fin: true,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
        Assert.True(dataSentSnapshot.HasFinalSize);
        Assert.Equal(0UL, dataSentSnapshot.FinalSize);
        Assert.Equal(0UL, dataSentSnapshot.UniqueBytesSent);
        Assert.Equal(0UL, state.ConnectionUniqueBytesSent);
    }
}
