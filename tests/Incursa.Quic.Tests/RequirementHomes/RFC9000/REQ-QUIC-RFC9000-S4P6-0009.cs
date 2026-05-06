namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0009")]
public sealed class REQ_QUIC_RFC9000_S4P6_0009
{
    [Theory]
    [InlineData(true, 1UL)]
    [InlineData(false, 3UL)]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AcceptsStreamIdsWithinTheAdvertisedLimit(
        bool bidirectional,
        ulong streamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: bidirectional ? 1UL : 4UL,
            incomingUnidirectionalStreamLimit: bidirectional ? 4UL : 1UL);

        byte[] allowedPacket = QuicStreamTestData.BuildStreamFrame(0x0A, streamId, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(allowedPacket, out QuicStreamFrame allowedFrame));

        Assert.True(state.TryReceiveStreamFrame(allowedFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }

    [Theory]
    [InlineData(true, 1UL)]
    [InlineData(false, 3UL)]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0009")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_RejectsFirstIncomingStreamWhenAdvertisedLimitIsZero(
        bool bidirectional,
        ulong streamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: bidirectional ? 0UL : 4UL,
            incomingUnidirectionalStreamLimit: bidirectional ? 4UL : 0UL);

        byte[] blockedPacket = QuicStreamTestData.BuildStreamFrame(0x0A, streamId, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(blockedPacket, out QuicStreamFrame blockedFrame));

        Assert.False(state.TryReceiveStreamFrame(blockedFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(streamId, out _));
    }

    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0009">An endpoint that receives a frame with a stream ID exceeding the limit it has sent MUST treat this as a connection error of type STREAM_LIMIT_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsOverLimitStreamIds()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(incomingBidirectionalStreamLimit: 1);

        byte[] overLimitPacket = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 5, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(overLimitPacket, out QuicStreamFrame overLimitFrame));

        Assert.False(state.TryReceiveStreamFrame(overLimitFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }
}
