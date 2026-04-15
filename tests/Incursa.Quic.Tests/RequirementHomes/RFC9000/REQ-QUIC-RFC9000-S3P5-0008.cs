namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0008">An endpoint SHOULD copy the error code from the STOP_SENDING frame to the RESET_STREAM frame it sends.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0008")]
public sealed class REQ_QUIC_RFC9000_S3P5_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_CopiesTheApplicationProtocolErrorCodeIntoTheResetStreamFrame()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x66),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0x66UL, resetStreamFrame.ApplicationProtocolErrorCode);

        Assert.True(state.TryGetSendAbortErrorCode(streamId.Value, out ulong sendAbortErrorCode));
        Assert.Equal(0x66UL, sendAbortErrorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasSendAbortErrorCode);
        Assert.Equal(0x66UL, snapshot.SendAbortErrorCode);
    }
}
