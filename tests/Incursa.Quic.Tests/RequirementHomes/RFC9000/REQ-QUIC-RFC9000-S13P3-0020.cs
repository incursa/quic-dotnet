namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0020">The limit on streams of a given type MUST be sent in MAX_STREAMS frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0020")]
public sealed class REQ_QUIC_RFC9000_S13P3_0020
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryPeekPeerStreamCapacityRelease_OffersTheCurrentUnidirectionalStreamLimitAfterThePeerStreamCloses()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingUnidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 3, streamData: []),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryPeekPeerStreamCapacityRelease(3, out QuicMaxStreamsFrame releaseFrame));
        Assert.False(releaseFrame.IsBidirectional);
        Assert.Equal(2UL, releaseFrame.MaximumStreams);

        Assert.True(state.TryCommitPeerStreamCapacityRelease(3, releaseFrame));
        Assert.Equal(2UL, state.IncomingUnidirectionalStreamLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryPeekPeerStreamCapacityRelease_OffersTheCurrentBidirectionalStreamLimitAfterThePeerStreamCloses()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 1, streamData: []),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryAbortLocalStreamWrites(1, out ulong finalSize, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, finalSize);

        Assert.True(state.TryPeekPeerStreamCapacityRelease(1, out QuicMaxStreamsFrame maxStreamsFrame));
        Assert.True(maxStreamsFrame.IsBidirectional);
        Assert.Equal(2UL, maxStreamsFrame.MaximumStreams);

        Assert.True(state.TryCommitPeerStreamCapacityRelease(1, maxStreamsFrame));
        Assert.Equal(2UL, state.IncomingBidirectionalStreamLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryPeekPeerStreamCapacityRelease_ReturnsFalseWhileThePeerBidirectionalStreamIsStillOpen()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, streamData: [0x51]),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryPeekPeerStreamCapacityRelease(1, out _));
    }
}

[Requirement("REQ-QUIC-RFC9000-S13P3-0020")]
public sealed class QuicConnectionStreamStateAbortBothCapacityRelease
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryPeekPeerStreamCapacityRelease_OffersTheCurrentBidirectionalStreamLimitAfterResetStreamIsAcknowledged()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingBidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0B, streamId: 1, streamData: []),
            out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryAbortLocalStreamWrites(1, out ulong finalSize, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0UL, finalSize);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(1, 0x44, finalSize),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);

        Assert.True(state.TryAcknowledgeReset(1));

        Assert.True(state.TryPeekPeerStreamCapacityRelease(1, out QuicMaxStreamsFrame releaseFrame));
        Assert.True(releaseFrame.IsBidirectional);
        Assert.Equal(2UL, releaseFrame.MaximumStreams);

        Assert.True(state.TryCommitPeerStreamCapacityRelease(1, releaseFrame));
        Assert.Equal(2UL, state.IncomingBidirectionalStreamLimit);
    }
}
