namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0006">Once a final size for a stream is known, it MUST NOT change.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P5-0006")]
public sealed class REQ_QUIC_RFC9000_S4P5_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReserveSendCapacity_MakesFinalSizeImmutableAfterItIsKnown()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 32,
            localUnidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 4,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesSent);
        Assert.Equal(2UL, state.ConnectionUniqueBytesSent);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: true,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesSent);
        Assert.Equal(2UL, state.ConnectionUniqueBytesSent);
    }
}
