namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0014")]
public sealed class REQ_QUIC_RFC9000_S19P10_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_RejectsEarlyDataRememberedStreamDataLimitViolations()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 3,
            peerBidirectionalReceiveLimit: 3);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x10, 0x11], offset: 0),
            out QuicStreamFrame firstEarlyDataFrame));
        Assert.True(state.TryReceiveStreamFrame(firstEarlyDataFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x12, 0x13], offset: 2),
            out QuicStreamFrame violatingEarlyDataFrame));

        Assert.False(state.TryReceiveStreamFrame(violatingEarlyDataFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_AcceptsEarlyDataWithinRememberedStreamDataLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 4);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x10, 0x11, 0x12, 0x13], offset: 0),
            out QuicStreamFrame earlyDataFrame));

        Assert.True(state.TryReceiveStreamFrame(earlyDataFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_RejectsEarlyDataFinalSizeBeyondRememberedStreamDataLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 3,
            peerBidirectionalReceiveLimit: 3);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [], offset: 4),
            out QuicStreamFrame violatingFinFrame));

        Assert.False(state.TryReceiveStreamFrame(violatingFinFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }
}
