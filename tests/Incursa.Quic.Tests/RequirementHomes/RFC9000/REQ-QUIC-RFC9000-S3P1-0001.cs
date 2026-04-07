namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P1-0001")]
public sealed class REQ_QUIC_RFC9000_S3P1_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_InitializesReadyAsANewlyCreatedSendableStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(0UL, snapshot.UniqueBytesSent);
    }
}
