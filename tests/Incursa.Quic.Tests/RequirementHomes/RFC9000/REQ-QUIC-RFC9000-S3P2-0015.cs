namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0015">When a STREAM frame with a FIN bit is received, the final size of the stream MUST be known.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0015")]
public sealed class REQ_QUIC_RFC9000_S3P2_0015
{
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
