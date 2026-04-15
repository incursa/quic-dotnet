namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0010">From the Data Sent state, the endpoint MUST retransmit stream data only as necessary.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P1-0010")]
public sealed class REQ_QUIC_RFC9000_S3P1_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_AllowsRetransmissionOfAlreadySentDataAfterDataSent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 3,
            localUnidirectionalSendLimit: 3);

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

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 3,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot retransmitSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, retransmitSnapshot.SendState);
        Assert.True(retransmitSnapshot.HasFinalSize);
        Assert.Equal(3UL, retransmitSnapshot.FinalSize);
        Assert.Equal(3UL, retransmitSnapshot.UniqueBytesSent);
        Assert.Equal(3UL, state.ConnectionUniqueBytesSent);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_RejectsBytesBeyondTheKnownFinalSizeAfterDataSent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 3,
            localUnidirectionalSendLimit: 3);

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

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 3,
            length: 1,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.DataSent, snapshot.SendState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(3UL, snapshot.FinalSize);
        Assert.Equal(3UL, snapshot.UniqueBytesSent);
    }
}
