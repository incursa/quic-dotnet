namespace Incursa.Quic.Tests;

public sealed class QuicConnectionStreamStateFlowControlFuzzTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_FinalSizeRegressionIsRejectedForSendAndReceive()
    {
        Random random = new(0x5150_2033);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            int payloadLength = random.Next(2, 33);
            int splitPoint = random.Next(1, payloadLength);

            byte[] payload = new byte[payloadLength];
            random.NextBytes(payload);

            QuicConnectionStreamState receiveState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 256,
                peerBidirectionalReceiveLimit: 64);

            ulong streamId = 1;
            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x08, streamId, payload[splitPoint..], (ulong)splitPoint),
                out QuicStreamFrame leadingFrame));
            Assert.True(receiveState.TryReceiveStreamFrame(leadingFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            int regressionLength = random.Next(1, splitPoint + 1);
            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0F, streamId, payload[..regressionLength], 0),
                out QuicStreamFrame regressionFrame));
            Assert.False(receiveState.TryReceiveStreamFrame(regressionFrame, out errorCode));
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

            QuicConnectionStreamState sendState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 256,
                localUnidirectionalSendLimit: 64);

            Assert.True(sendState.TryOpenLocalStream(bidirectional: false, out QuicStreamId localStreamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            Assert.True(sendState.TryReserveSendCapacity(
                localStreamId.Value,
                offset: (ulong)splitPoint,
                length: payloadLength - splitPoint,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);

            int sendRegressionLength = random.Next(1, splitPoint + 1);
            Assert.False(sendState.TryReserveSendCapacity(
                localStreamId.Value,
                offset: 0,
                length: sendRegressionLength,
                fin: true,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
        }
    }
}
