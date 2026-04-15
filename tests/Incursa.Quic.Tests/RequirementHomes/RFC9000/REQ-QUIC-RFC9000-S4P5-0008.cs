namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0008">A receiver SHOULD treat receipt of data at or beyond the final size as an error of type FINAL_SIZE_ERROR, even after a stream is closed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P5-0008")]
public sealed class REQ_QUIC_RFC9000_S4P5_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_ClosesTheStreamAfterAllFinalSizeBytesAreDelivered()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x11, 0x22, 0x33, 0x44], offset: 0),
            out QuicStreamFrame finFrame));

        Assert.True(state.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot preReadSnapshot));
        Assert.True(preReadSnapshot.HasFinalSize);
        Assert.Equal(4UL, preReadSnapshot.FinalSize);
        Assert.Equal(QuicStreamReceiveState.DataRecvd, preReadSnapshot.ReceiveState);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
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
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination));
        Assert.NotEqual(default, maxDataFrame);
        Assert.NotEqual(default, maxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TryReceiveStreamFrame_RejectsDataAtOrBeyondFinalSize()
    {
        Random random = new(0x5150_2042);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            int payloadLength = random.Next(1, 33);
            byte[] payload = new byte[payloadLength];
            random.NextBytes(payload);

            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 256,
                peerBidirectionalReceiveLimit: 64);

            ulong streamId = 1;
            byte[] finPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId, payload, 0);
            Assert.True(QuicStreamParser.TryParseStreamFrame(finPacket, out QuicStreamFrame finFrame));
            Assert.True(state.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
            Assert.True(snapshot.HasFinalSize);
            Assert.Equal((ulong)payloadLength, snapshot.FinalSize);
            Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);

            ulong extraOffset = iteration % 2 == 0 ? snapshot.FinalSize : snapshot.FinalSize + 1;
            byte[] extraPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId, [0xFF], extraOffset);
            Assert.True(QuicStreamParser.TryParseStreamFrame(extraPacket, out QuicStreamFrame extraFrame));
            Assert.False(state.TryReceiveStreamFrame(extraFrame, out errorCode));
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsDataAtFinalSizeAfterTheStreamIsClosed()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x11, 0x22, 0x33, 0x44], offset: 0),
            out QuicStreamFrame finFrame));

        Assert.True(state.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
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
        Assert.NotEqual(default, maxDataFrame);
        Assert.NotEqual(default, maxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x55], offset: snapshot.FinalSize),
            out QuicStreamFrame extraFrame));

        Assert.False(state.TryReceiveStreamFrame(extraFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(4UL, snapshot.ReadOffset);
    }
}
