namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0018">Like MAX_DATA, an updated value MUST be sent when the packet containing the most recent MAX_STREAM_DATA frame for a stream is lost or when the limit is updated.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
public sealed class REQ_QUIC_RFC9000_S13P3_0018
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_UpdatesTheCurrentStreamDataOffsetWhenAdditionalBytesAreRead()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame firstFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[3];
        Assert.True(state.TryReadStreamData(
            1,
            destination[..2],
            out int bytesWritten,
            out bool completed,
            out _,
            out QuicMaxStreamDataFrame firstMaxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.Equal(1UL, firstMaxStreamDataFrame.StreamId);
        Assert.Equal(10UL, firstMaxStreamDataFrame.MaximumStreamData);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x33, 0x44, 0x55], offset: 2),
            out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out _,
            out QuicMaxStreamDataFrame secondMaxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(3, bytesWritten);
        Assert.False(completed);
        Assert.Equal(1UL, secondMaxStreamDataFrame.StreamId);
        Assert.Equal(13UL, secondMaxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(13UL, snapshot.ReceiveLimit);
    }
}
