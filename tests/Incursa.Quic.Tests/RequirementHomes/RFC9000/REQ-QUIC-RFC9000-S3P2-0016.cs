namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P2-0016")]
public sealed class REQ_QUIC_RFC9000_S3P2_0016
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_EntersSizeKnownWhenFinArrives()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionReceiveLimit: 32, peerBidirectionalReceiveLimit: 8);

        byte[] nonFinPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 5, [0x33, 0x44], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(nonFinPacket, out QuicStreamFrame nonFinFrame));

        Assert.True(state.TryReceiveStreamFrame(nonFinFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot preFinSnapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, preFinSnapshot.ReceiveState);
        Assert.False(preFinSnapshot.HasFinalSize);

        byte[] finPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [0x33, 0x44], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(finPacket, out QuicStreamFrame finFrame));

        Assert.True(state.TryReceiveStreamFrame(finFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
    }
}
