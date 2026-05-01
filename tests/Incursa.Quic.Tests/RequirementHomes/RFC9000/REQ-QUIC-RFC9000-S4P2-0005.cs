namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P2-0005">A receiver MUST NOT wait for a STREAM_DATA_BLOCKED or DATA_BLOCKED frame before sending a MAX_STREAM_DATA or MAX_DATA frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P2-0005")]
public sealed class REQ_QUIC_RFC9000_S4P2_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_SendsCreditWithoutWaitingForBlockedSignals()
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
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(10UL, maxStreamDataFrame.MaximumStreamData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamDataBlockedFrame_DoesNotAdvertiseCreditWithoutApplicationConsumption()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(streamId: 1, maximumStreamData: 8),
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(16UL, state.ConnectionReceiveLimit);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(8UL, snapshot.ReceiveLimit);
        Assert.Equal(0UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);

        Span<byte> destination = stackalloc byte[1];
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
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_UsesConsumedBytesAfterPriorBlockedSignal()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(streamId: 1, maximumStreamData: 8),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out errorCode));
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
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(10UL, maxStreamDataFrame.MaximumStreamData);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(10UL, snapshot.ReceiveLimit);
        Assert.Equal(2UL, snapshot.ReadOffset);
    }
}
