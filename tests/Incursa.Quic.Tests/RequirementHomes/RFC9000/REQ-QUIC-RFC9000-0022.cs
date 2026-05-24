namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0022")]
public sealed class REQ_QUIC_RFC9000_0022
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AllowsInterleavedDataOnDifferentPeerStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 1, [0x11]), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 5, [0x51]), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 1, [0x12], offset: 1), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(2UL, firstSnapshot.UniqueBytesReceived);
        Assert.Equal(1UL, secondSnapshot.UniqueBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_DoesNotMixBytesAcrossInterleavedStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 1, [0x21]), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 5, [0x51]), out errorCode));
        Assert.Equal(default, errorCode);

        byte[] destination = new byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1, bytesWritten);
        Assert.False(completed);
        Assert.Equal(0x21, destination[0]);
        Assert.Equal(0, destination[1]);
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] streamData, ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, streamData, offset),
            out QuicStreamFrame frame));

        return frame;
    }
}
