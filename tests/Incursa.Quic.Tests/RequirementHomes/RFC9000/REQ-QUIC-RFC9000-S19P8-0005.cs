namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0005")]
public sealed class REQ_QUIC_RFC9000_S19P8_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_PreservesZeroLengthPayloadOffsets()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x02,
            streamData: [],
            offset: 0x1A2B3C4D);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.Equal((ulong)0x1A2B3C4D, frame.Offset);
        Assert.True(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.True(frame.StreamData.IsEmpty);
        Assert.Equal(packet.Length, frame.ConsumedLength);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frame.FrameType,
            frame.StreamId.Value,
            frame.Offset,
            frame.StreamData,
            destination,
            out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
