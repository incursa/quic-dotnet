namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0010">An endpoint MUST terminate a connection with an error of type STREAM_LIMIT_ERROR if a peer opens more streams than was permitted.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P11-0010")]
public sealed class REQ_QUIC_RFC9000_S19P11_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AllowsTheFirstPeerInitiatedStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: 1);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, [0x11, 0x22], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(2, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsAPeerInitiatedStreamThatExceedsTheLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: 1);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 5, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.False(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }
}
