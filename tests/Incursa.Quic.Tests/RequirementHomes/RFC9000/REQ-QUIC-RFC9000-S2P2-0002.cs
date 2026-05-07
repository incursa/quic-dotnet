namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0002">An endpoint MUST use the Stream ID and Offset fields in STREAM frames to place data in order.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P2-0002")]
public sealed class REQ_QUIC_RFC9000_S2P2_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_DeliversBufferedFragmentsInOffsetOrder()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [0x33, 0x44], offset: 2),
            out QuicStreamFrame tailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 5, [0x11, 0x22], offset: 0),
            out QuicStreamFrame headFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot sizeKnownSnapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, sizeKnownSnapshot.ReceiveState);
        Assert.True(sizeKnownSnapshot.HasFinalSize);
        Assert.Equal(4UL, sizeKnownSnapshot.FinalSize);
        Assert.Equal(2UL, sizeKnownSnapshot.UniqueBytesReceived);
        Assert.Equal(2, sizeKnownSnapshot.BufferedReadableBytes);

        Assert.False(state.TryReadStreamData(
            5,
            stackalloc byte[4],
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);

        Assert.True(state.TryReceiveStreamFrame(headFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
            5,
            destination,
            out bytesWritten,
            out completed,
            out maxDataFrame,
            out maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(20UL, maxDataFrame.MaximumData);
        Assert.Equal(5UL, maxStreamDataFrame.StreamId);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_LeavesOutOfOrderTailBufferedUntilTheMissingPrefixArrives()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [0x33, 0x44], offset: 2),
            out QuicStreamFrame tailFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(2, snapshot.BufferedReadableBytes);

        Span<byte> destination = stackalloc byte[4];
        Assert.False(state.TryReadStreamData(
            5,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(5, out snapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
        Assert.Equal(0UL, snapshot.ReadOffset);
        Assert.Equal(2, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_KeepsIdenticalOffsetsOnDifferentStreamsIndependent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [0x33, 0x44], offset: 2),
            out QuicStreamFrame firstTailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 9, [0x55, 0x66], offset: 2),
            out QuicStreamFrame secondTailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 9, [0x11, 0x22], offset: 0),
            out QuicStreamFrame secondHeadFrame));

        Assert.True(state.TryReceiveStreamFrame(firstTailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(secondTailFrame, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(secondHeadFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
            9,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x55, 0x66 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(36UL, maxDataFrame.MaximumData);
        Assert.Equal(9UL, maxStreamDataFrame.StreamId);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, firstSnapshot.ReceiveState);
        Assert.Equal(0UL, firstSnapshot.ReadOffset);
        Assert.Equal(2, firstSnapshot.BufferedReadableBytes);

        Assert.True(state.TryGetStreamSnapshot(9, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, secondSnapshot.ReceiveState);
        Assert.Equal(4UL, secondSnapshot.ReadOffset);
        Assert.Equal(0, secondSnapshot.BufferedReadableBytes);
    }
}
