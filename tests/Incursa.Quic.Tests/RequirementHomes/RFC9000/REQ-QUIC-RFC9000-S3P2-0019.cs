namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P2-0019")]
public sealed class REQ_QUIC_RFC9000_S3P2_0019
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0019")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_KeepsDataRecvdUntilApplicationReadsIt()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionReceiveLimit: 32, peerBidirectionalReceiveLimit: 8);
        ulong streamId = 5;

        byte[] tail = QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [0x33, 0x44], offset: 2);
        byte[] head = QuicStreamTestData.BuildStreamFrame(0x0E, streamId, [0x11, 0x22], offset: 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(tail, out QuicStreamFrame tailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(head, out QuicStreamFrame headFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(headFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
        Assert.NotEqual(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(4UL, snapshot.UniqueBytesReceived);
    }
}
