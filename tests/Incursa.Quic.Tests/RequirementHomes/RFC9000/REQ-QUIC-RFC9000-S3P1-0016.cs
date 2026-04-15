namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0016">An endpoint MAY send a RESET_STREAM as the first frame that mentions a stream, causing the sending part of that stream to open and then immediately transition to the Reset Sent state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P1-0016")]
public sealed class REQ_QUIC_RFC9000_S3P1_0016
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAbortLocalStreamWrites_OpensTheNextLocalStreamWhenResetIsTheFirstFrame()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            localBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 8);

        Assert.False(state.TryGetStreamSnapshot(0, out _));

        Assert.True(state.TryAbortLocalStreamWrites(0, out ulong finalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, finalSize);

        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(0UL, snapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0016")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAbortLocalStreamWrites_RejectsPeerInitiatedStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.False(state.TryAbortLocalStreamWrites(1, out ulong finalSize, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, finalSize);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(1, out _));
    }
}
