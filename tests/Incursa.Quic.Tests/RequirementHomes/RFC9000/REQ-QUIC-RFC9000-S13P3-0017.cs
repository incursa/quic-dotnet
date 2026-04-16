namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0017">The current maximum stream data offset MUST be sent in MAX_STREAM_DATA frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0017")]
public sealed class REQ_QUIC_RFC9000_S13P3_0017
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_SendsTheCurrentStreamDataOffsetAfterARead()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(10UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(10UL, snapshot.ReceiveLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_DoesNotEmitStreamCreditWhenNoBytesAreRead()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReadStreamData(
            1,
            Span<byte>.Empty,
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

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0UL, snapshot.ReadOffset);
        Assert.Equal(8UL, snapshot.ReceiveLimit);
        Assert.Equal(2, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0017")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_LeavesStreamCreditAtTheMaximumFlowControlLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: QuicVariableLengthInteger.MaxValue);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, snapshot.ReceiveLimit);
        Assert.Equal(2UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }
}
