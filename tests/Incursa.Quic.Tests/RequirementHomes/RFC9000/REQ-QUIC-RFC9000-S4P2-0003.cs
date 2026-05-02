namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P2-0003">An endpoint MAY send frames related to flow control only when there are other frames to send, ensuring that flow control does not cause extra packets to be sent.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P2-0003")]
public sealed class REQ_QUIC_RFC9000_S4P2_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_MakesCreditFramesAvailableForOpportunisticSerialization()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[16];
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

        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(maxDataFrame, destination, out int maxDataBytesWritten));
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(destination[..maxDataBytesWritten], out QuicMaxDataFrame parsedMaxDataFrame, out int maxDataBytesConsumed));
        Assert.Equal(maxDataFrame, parsedMaxDataFrame);
        Assert.Equal(maxDataBytesWritten, maxDataBytesConsumed);

        Assert.True(QuicFrameCodec.TryFormatMaxStreamDataFrame(maxStreamDataFrame, destination, out int maxStreamDataBytesWritten));
        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(destination[..maxStreamDataBytesWritten], out QuicMaxStreamDataFrame parsedMaxStreamDataFrame, out int maxStreamDataBytesConsumed));
        Assert.Equal(maxStreamDataFrame, parsedMaxStreamDataFrame);
        Assert.Equal(maxStreamDataBytesWritten, maxStreamDataBytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_DoesNotCreateCreditFramesWhenNoApplicationBytesAreRead()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = [];
        Assert.False(state.TryReadStreamData(
            1,
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
        Assert.Equal(16UL, state.ConnectionReceiveLimit);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(8UL, snapshot.ReceiveLimit);
        Assert.Equal(0UL, snapshot.ReadOffset);
        Assert.Equal(2, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_PublishesOnlyCreditForBytesConsumedByPartialReads()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[1];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1, bytesWritten);
        Assert.False(completed);
        Assert.Equal(0x11, destination[0]);
        Assert.Equal(17UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(9UL, maxStreamDataFrame.MaximumStreamData);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(9UL, snapshot.ReceiveLimit);
        Assert.Equal(1UL, snapshot.ReadOffset);
        Assert.Equal(1, snapshot.BufferedReadableBytes);

        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out maxDataFrame,
            out maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1, bytesWritten);
        Assert.False(completed);
        Assert.Equal(0x22, destination[0]);
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(10UL, maxStreamDataFrame.MaximumStreamData);
        Assert.True(state.TryGetStreamSnapshot(1, out snapshot));
        Assert.Equal(10UL, snapshot.ReceiveLimit);
        Assert.Equal(2UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }
}
