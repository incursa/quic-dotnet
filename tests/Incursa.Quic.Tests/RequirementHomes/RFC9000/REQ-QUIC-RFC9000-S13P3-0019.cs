namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0019">An endpoint SHOULD stop sending MAX_STREAM_DATA frames when the receiving part of the stream enters a Size Known or Reset Recvd state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0019")]
public sealed class REQ_QUIC_RFC9000_S13P3_0019
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0019")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_StopsAdvertisingStreamCreditOnceTheStreamIsClosedOrReset()
    {
        QuicConnectionStreamState closedState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x11, 0x22, 0x33, 0x44], offset: 0),
            out QuicStreamFrame finFrame));
        Assert.True(closedState.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(closedState.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.True(completed);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(closedState.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot closedSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, closedSnapshot.ReceiveState);

        Assert.False(closedState.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out maxDataFrame,
            out maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.True(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);

        QuicConnectionStreamState resetState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x55, 0x66], offset: 0),
            out QuicStreamFrame resetFrame));
        Assert.True(resetState.TryReceiveStreamFrame(resetFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(resetState.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);

        Assert.False(resetState.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out maxDataFrame,
            out maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);

        Assert.True(resetState.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot resetSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, resetSnapshot.ReceiveState);
    }
}
