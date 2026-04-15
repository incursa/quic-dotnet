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
}
