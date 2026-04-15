namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0013">An endpoint MUST buffer received stream data for ordered delivery.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0013")]
public sealed class REQ_QUIC_RFC9000_S3P2_0013
{
    [Fact]
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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_LeavesOutOfOrderTailBufferedUntilMissingPrefixArrives()
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
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TryReceiveStreamFrame_BuffersOutOfOrderFragmentsForOrderedDelivery()
    {
        Random random = new(0x5150_2030);
        ulong streamId = 1;

        for (int iteration = 0; iteration < 128; iteration++)
        {
            int payloadLength = random.Next(1, 33);
            byte[] payload = new byte[payloadLength];
            random.NextBytes(payload);

            List<(ulong Offset, byte[] Data, bool Fin)> fragments = [];
            int cursor = 0;
            while (cursor < payloadLength)
            {
                int remaining = payloadLength - cursor;
                int fragmentLength = random.Next(1, remaining + 1);
                fragments.Add(((ulong)cursor, payload[cursor..(cursor + fragmentLength)], cursor + fragmentLength == payloadLength));
                cursor += fragmentLength;
            }

            fragments = fragments.OrderBy(_ => random.Next()).ToList();

            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 512,
                connectionSendLimit: 512,
                incomingBidirectionalStreamLimit: 4,
                incomingUnidirectionalStreamLimit: 4,
                peerBidirectionalStreamLimit: 4,
                peerUnidirectionalStreamLimit: 4,
                localBidirectionalReceiveLimit: 128,
                peerBidirectionalReceiveLimit: 128,
                peerUnidirectionalReceiveLimit: 128,
                localBidirectionalSendLimit: 128,
                localUnidirectionalSendLimit: 128,
                peerBidirectionalSendLimit: 128);

            foreach ((ulong offset, byte[] data, bool fin) in fragments)
            {
                byte frameType = (byte)(fin ? 0x0F : 0x0E);
                byte[] packet = QuicStreamTestData.BuildStreamFrame(frameType, streamId, data, offset);
                Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
                Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
                Assert.Equal(default, errorCode);
            }

            byte[] destination = new byte[payloadLength];
            Assert.True(state.TryReadStreamData(
                streamId,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out QuicTransportErrorCode readErrorCode));
            Assert.Equal(default, readErrorCode);
            Assert.Equal(payloadLength, bytesWritten);
            Assert.True(completed);
            Assert.True(payload.AsSpan().SequenceEqual(destination));
        }
    }
}
