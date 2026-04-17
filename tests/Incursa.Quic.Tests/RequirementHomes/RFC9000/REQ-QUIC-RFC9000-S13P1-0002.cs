namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P1-0002">For STREAM frames, this means the data has been enqueued in preparation to be received by the application protocol, but it does not require that data be delivered and consumed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P1-0002")]
public sealed class REQ_QUIC_RFC9000_S13P1_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_EnqueuesStreamDataBeforeTheApplicationConsumesIt()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0UL, snapshot.ReadOffset);
        Assert.Equal(2, snapshot.BufferedReadableBytes);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P1-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_WithAnEmptyDestinationLeavesStreamDataBuffered()
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
        Assert.Equal(2, snapshot.BufferedReadableBytes);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }
}
