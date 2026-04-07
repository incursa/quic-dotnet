namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0013">An endpoint MUST buffer received stream data for ordered delivery.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0013")]
public sealed class REQ_QUIC_RFC9000_S3P2_0013
{
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
