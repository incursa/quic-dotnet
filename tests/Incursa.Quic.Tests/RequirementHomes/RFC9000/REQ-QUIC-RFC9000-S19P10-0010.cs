namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0010")]
public sealed class REQ_QUIC_RFC9000_S19P10_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_TreatsMaximumStreamDataAsAnAbsoluteByteOffset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            connectionSendLimit: 32);

        Assert.True(state.TryOpenLocalStream(true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 10), out QuicTransportErrorCode errorCode));
        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 14), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(14UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_IgnoresMaximumStreamDataThatDoesNotIncreaseTheLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            connectionSendLimit: 32);

        Assert.True(state.TryOpenLocalStream(true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 9), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(10UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamDataFrame_PreservesMaximumStreamDataAtTheVarintLimit()
    {
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(
            streamId: 1,
            maximumStreamData: QuicVariableLengthInteger.MaxValue);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertParses(
            encoded,
            expectedStreamId: 1,
            expectedMaximumStreamData: QuicVariableLengthInteger.MaxValue);
    }
}
