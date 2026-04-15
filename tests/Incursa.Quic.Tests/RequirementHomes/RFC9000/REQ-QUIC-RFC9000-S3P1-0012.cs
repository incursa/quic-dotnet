namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0012">An endpoint in the Data Sent state MAY safely ignore any MAX_STREAM_DATA frames it receives from its peer for that stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P1-0012")]
public sealed class REQ_QUIC_RFC9000_S3P1_0012
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_PreservesDataSentAfterPeerCreditIncrease()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();
        QuicStreamId streamId = EnterDataSentState(state);

        state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 12), out QuicTransportErrorCode errorCode);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot afterSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, afterSnapshot.SendState);
        Assert.True(afterSnapshot.HasFinalSize);
        Assert.Equal(3UL, afterSnapshot.FinalSize);
        Assert.Equal(3UL, afterSnapshot.UniqueBytesSent);
        Assert.Equal(3UL, state.ConnectionUniqueBytesSent);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 3,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_PreservesDataSentAfterStalePeerCredit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();
        QuicStreamId streamId = EnterDataSentState(state);

        state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 7), out QuicTransportErrorCode errorCode);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot afterSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, afterSnapshot.SendState);
        Assert.True(afterSnapshot.HasFinalSize);
        Assert.Equal(3UL, afterSnapshot.FinalSize);
        Assert.Equal(3UL, afterSnapshot.UniqueBytesSent);
        Assert.Equal(3UL, state.ConnectionUniqueBytesSent);
    }

    private static QuicStreamId EnterDataSentState(QuicConnectionStreamState state)
    {
        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

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
        Assert.Equal(3UL, state.ConnectionUniqueBytesSent);

        return streamId;
    }
}
