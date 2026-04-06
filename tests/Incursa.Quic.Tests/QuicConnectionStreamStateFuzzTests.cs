namespace Incursa.Quic.Tests;

public sealed class QuicConnectionStreamStateFuzzTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0014")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0017")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0020")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_ReceiveStreamFrame_ReassemblesRandomFragmentOrders()
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

            QuicConnectionStreamState state = new(
                new QuicConnectionStreamStateOptions(
                    IsServer: false,
                    InitialConnectionReceiveLimit: 512,
                    InitialConnectionSendLimit: 512,
                    InitialIncomingBidirectionalStreamLimit: 4,
                    InitialIncomingUnidirectionalStreamLimit: 4,
                    InitialPeerBidirectionalStreamLimit: 4,
                    InitialPeerUnidirectionalStreamLimit: 4,
                    InitialLocalBidirectionalReceiveLimit: 128,
                    InitialPeerBidirectionalReceiveLimit: 128,
                    InitialPeerUnidirectionalReceiveLimit: 128,
                    InitialLocalBidirectionalSendLimit: 128,
                    InitialLocalUnidirectionalSendLimit: 128,
                    InitialPeerBidirectionalSendLimit: 128));

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

            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal((ulong)payloadLength, snapshot.AccountedBytesReceived);
            Assert.Equal((ulong)payloadLength, snapshot.UniqueBytesReceived);
            Assert.Equal((ulong)payloadLength, snapshot.ReadOffset);
            Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0017")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0018")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0019")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_SendCapacity_ReachesDataSentOnlyAfterOrderedFragments()
    {
        Random random = new(0x5150_2031);

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

            QuicConnectionStreamState state = new(
                new QuicConnectionStreamStateOptions(
                    IsServer: false,
                    InitialConnectionReceiveLimit: 512,
                    InitialConnectionSendLimit: 512,
                    InitialIncomingBidirectionalStreamLimit: 4,
                    InitialIncomingUnidirectionalStreamLimit: 4,
                    InitialPeerBidirectionalStreamLimit: 4,
                    InitialPeerUnidirectionalStreamLimit: 4,
                    InitialLocalBidirectionalReceiveLimit: 128,
                    InitialPeerBidirectionalReceiveLimit: 128,
                    InitialPeerUnidirectionalReceiveLimit: 128,
                    InitialLocalBidirectionalSendLimit: 128,
                    InitialLocalUnidirectionalSendLimit: 128,
                    InitialPeerBidirectionalSendLimit: 128));

            Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            foreach ((ulong offset, byte[] data, bool fin) in fragments)
            {
                Assert.True(state.TryReserveSendCapacity(
                    streamId.Value,
                    offset,
                    data.Length,
                    fin,
                    out QuicDataBlockedFrame dataBlockedFrame,
                    out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                    out QuicTransportErrorCode errorCode));
                Assert.Equal(default, dataBlockedFrame);
                Assert.Equal(default, streamDataBlockedFrame);
                Assert.Equal(default, errorCode);

                Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
                if (fin)
                {
                    Assert.Equal(QuicStreamSendState.DataSent, snapshot.SendState);
                    Assert.True(snapshot.HasFinalSize);
                    Assert.Equal((ulong)payloadLength, snapshot.FinalSize);
                }
                else
                {
                    Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
                    Assert.False(snapshot.HasFinalSize);
                }
            }

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot completedSnapshot));
            Assert.Equal((ulong)payloadLength, completedSnapshot.UniqueBytesSent);
            Assert.Equal(QuicStreamSendState.DataSent, completedSnapshot.SendState);

            Assert.False(state.TryReserveSendCapacity(
                streamId.Value,
                offset: (ulong)payloadLength,
                length: 1,
                fin: false,
                out QuicDataBlockedFrame finalDataBlockedFrame,
                out QuicStreamDataBlockedFrame finalStreamDataBlockedFrame,
                out QuicTransportErrorCode finalErrorCode));
            Assert.Equal(default, finalDataBlockedFrame);
            Assert.Equal(default, finalStreamDataBlockedFrame);
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, finalErrorCode);
        }
    }
}
