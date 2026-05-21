namespace Incursa.Quic.Tests;

public sealed class QuicConnectionAckHelpersTests
{
    [Fact]
    public void EnumerateAcknowledgedPacketNumbers_ReturnsFirstRangeThenAdditionalRangesInOrder()
    {
        QuicAckFrame frame = new()
        {
            LargestAcknowledged = 10,
            FirstAckRange = 2,
            AdditionalRanges =
            [
                new QuicAckRange(gap: 0, ackRangeLength: 0, smallestAcknowledged: 5, largestAcknowledged: 6),
                new QuicAckRange(gap: 0, ackRangeLength: 0, smallestAcknowledged: 1, largestAcknowledged: 2),
            ],
        };

        Assert.Equal(
            [8UL, 9UL, 10UL, 5UL, 6UL, 1UL, 2UL],
            QuicConnectionAckHelpers.EnumerateAcknowledgedPacketNumbers(frame));
    }

    [Fact]
    public void TryBuildOutboundAckPayload_PadsToMinimumLengthAndPreservesAckBytes()
    {
        QuicAckFrame frame = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 3,
            AckDelay = 7,
            FirstAckRange = 0,
        };

        Assert.True(QuicConnectionAckHelpers.TryBuildOutboundAckPayload(frame, 64, out byte[] payload));
        Assert.Equal(64, payload.Length);
        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame parsedFrame, out int bytesConsumed));
        Assert.Equal(frame.LargestAcknowledged, parsedFrame.LargestAcknowledged);
        Assert.Equal(frame.AckDelay, parsedFrame.AckDelay);
        Assert.Equal(frame.FirstAckRange, parsedFrame.FirstAckRange);
        Assert.True(bytesConsumed > 0);
        Assert.True(bytesConsumed <= payload.Length);
    }

    [Fact]
    public void TryBuildApplicationAckPiggybackPayload_PrependsAckPayloadToApplicationPayload()
    {
        QuicSenderFlowController flowController = new();
        flowController.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        byte[] applicationPayload = [0x11, 0x22, 0x33];

        Assert.True(QuicConnectionAckHelpers.TryBuildApplicationAckPiggybackPayload(
            applicationPayload,
            flowController,
            nowMicros: 1_000,
            out byte[] piggybackedPayload,
            out QuicAckFrame ackFrame));

        Assert.True(QuicFrameCodec.TryParseAckFrame(piggybackedPayload, out QuicAckFrame parsedAckFrame, out int ackBytesConsumed));
        Assert.Equal(ackFrame.LargestAcknowledged, parsedAckFrame.LargestAcknowledged);
        Assert.Equal(ackFrame.FirstAckRange, parsedAckFrame.FirstAckRange);
        Assert.Equal(applicationPayload, piggybackedPayload[ackBytesConsumed..].ToArray());
    }
}
