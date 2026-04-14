namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0035">A receiver MUST accept packets containing an outdated frame, such as a MAX_DATA frame carrying a smaller maximum data value than one found in an older packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0035")]
public sealed class REQ_QUIC_RFC9000_S13P3_0035
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxDataFrame_AcceptsAnOutdatedMaximumDataFrame()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8);

        byte[] updatedFrameBytes = QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(12));
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(updatedFrameBytes, out QuicMaxDataFrame updatedFrame, out int updatedBytesConsumed));
        Assert.Equal(updatedFrameBytes.Length, updatedBytesConsumed);
        Assert.True(state.TryApplyMaxDataFrame(updatedFrame));
        Assert.Equal(12UL, state.ConnectionSendLimit);

        byte[] outdatedFrameBytes = QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(11));
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(outdatedFrameBytes, out QuicMaxDataFrame outdatedFrame, out int outdatedBytesConsumed));
        Assert.Equal(outdatedFrameBytes.Length, outdatedBytesConsumed);
        Assert.False(state.TryApplyMaxDataFrame(outdatedFrame));
        Assert.Equal(12UL, state.ConnectionSendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_IgnoresAnOutdatedMaximumStreamDataFrame()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8);

        byte[] updatedFrameBytes = QuicFrameTestData.BuildMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10));
        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(updatedFrameBytes, out QuicMaxStreamDataFrame updatedFrame, out int updatedBytesConsumed));
        Assert.Equal(updatedFrameBytes.Length, updatedBytesConsumed);
        Assert.True(state.TryApplyMaxStreamDataFrame(updatedFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] outdatedFrameBytes = QuicFrameTestData.BuildMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 9));
        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(outdatedFrameBytes, out QuicMaxStreamDataFrame outdatedFrame, out int outdatedBytesConsumed));
        Assert.Equal(outdatedFrameBytes.Length, outdatedBytesConsumed);
        Assert.False(state.TryApplyMaxStreamDataFrame(outdatedFrame, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(10UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxStreamsFrame_LeavesAnAlreadyAdvertisedLimitUnchanged()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 4);

        byte[] updatedFrameBytes = QuicFrameTestData.BuildMaxStreamsFrame(new QuicMaxStreamsFrame(true, 5));
        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(updatedFrameBytes, out QuicMaxStreamsFrame updatedFrame, out int updatedBytesConsumed));
        Assert.Equal(updatedFrameBytes.Length, updatedBytesConsumed);
        Assert.True(state.TryApplyMaxStreamsFrame(updatedFrame));
        Assert.Equal(5UL, state.PeerBidirectionalStreamLimit);

        byte[] equalFrameBytes = QuicFrameTestData.BuildMaxStreamsFrame(new QuicMaxStreamsFrame(true, 5));
        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(equalFrameBytes, out QuicMaxStreamsFrame equalFrame, out int equalBytesConsumed));
        Assert.Equal(equalFrameBytes.Length, equalBytesConsumed);
        Assert.False(state.TryApplyMaxStreamsFrame(equalFrame));
        Assert.Equal(5UL, state.PeerBidirectionalStreamLimit);
    }
}
