namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0015">When a STREAM frame with a FIN bit is received, the final size of the stream MUST be known.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0015")]
public sealed class REQ_QUIC_RFC9000_S3P2_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_MarksFinalSizeKnownWhenFinArrives()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        byte[] finPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [0x33, 0x44], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(finPacket, out QuicStreamFrame finFrame));

        Assert.True(state.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_LeavesFinalSizeUnknownWithoutFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        byte[] nonFinPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 5, [0x33, 0x44], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(nonFinPacket, out QuicStreamFrame nonFinFrame));

        Assert.True(state.TryReceiveStreamFrame(nonFinFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_MarksFinalSizeKnownOnZeroLengthFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        byte[] finPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [], offset: 4);
        Assert.True(QuicStreamParser.TryParseStreamFrame(finPacket, out QuicStreamFrame finFrame));

        Assert.True(state.TryReceiveStreamFrame(finFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
        Assert.Equal(0UL, snapshot.UniqueBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TryReceiveStreamFrame_MarksFinalSizeKnownWhenFinArrives()
    {
        Random random = new(0x5150_2041);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            int payloadLength = random.Next(1, 33);
            byte[] payload = new byte[payloadLength];
            random.NextBytes(payload);

            ulong streamId = 1;
            ulong offset = (ulong)random.Next(0, 16);

            byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0F, streamId, payload, offset);
            Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 256,
                peerBidirectionalReceiveLimit: 64);

            Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
            Assert.True(snapshot.HasFinalSize);
            Assert.Equal(offset + (ulong)payloadLength, snapshot.FinalSize);
            Assert.Equal((ulong)payloadLength, snapshot.UniqueBytesReceived);
        }
    }
}
