namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0013">An endpoint MUST NOT wait to receive STREAMS_BLOCKED before advertising additional credit.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P6-0013")]
public sealed class REQ_QUIC_RFC9000_S4P6_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryPeekPeerStreamCapacityRelease_OffersMoreUnidirectionalCreditAfterThePeerStreamCloses()
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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryPeekPeerStreamCapacityRelease_ReturnsFalseWhileThePeerStreamIsStillOpen()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            incomingUnidirectionalStreamLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 3, streamData: [0x51]),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryPeekPeerStreamCapacityRelease(3, out _));
    }
}
