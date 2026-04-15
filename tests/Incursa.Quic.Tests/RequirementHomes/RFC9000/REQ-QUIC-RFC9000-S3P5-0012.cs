namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0012">An endpoint MAY terminate one direction of a bidirectional stream by sending a RESET_STREAM frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0012")]
public sealed class REQ_QUIC_RFC9000_S3P5_0012
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAbortLocalStreamWrites_AllowsResetStreamOnBidirectionalStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryAbortLocalStreamWrites(streamId.Value, out ulong finalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, finalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(0UL, snapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAbortLocalStreamWrites_RejectsPeerInitiatedBidirectionalStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.False(state.TryAbortLocalStreamWrites(1, out ulong finalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, finalSize);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }
}
