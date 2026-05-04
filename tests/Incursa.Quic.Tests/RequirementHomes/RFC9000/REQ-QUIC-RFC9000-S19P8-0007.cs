namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0007")]
public sealed class REQ_QUIC_RFC9000_S19P8_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReceiveStreamFrame_RejectsUncreatedLocalBidirectionalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: false);
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(0x0A, streamId: 0x00, streamData: [0xAA]);

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryReceiveStreamFrame_AcceptsCreatedPeerBidirectionalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: false);
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(0x0A, streamId: 0x01, streamData: [0xAA]);

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryReceiveStreamFrame_RejectsCreatedLocalSendOnlyStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: false);
        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out _));
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(0x0A, streamId.Value, streamData: [0xAA]);

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
    }
}
