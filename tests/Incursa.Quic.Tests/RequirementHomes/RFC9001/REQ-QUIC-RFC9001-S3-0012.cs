namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0012")]
public sealed class REQ_QUIC_RFC9001_S3_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStreamFrame_RoundTripsAValidStreamFrame()
    {
        byte frameType = 0x0F;
        byte[] streamData = [0xAA, 0xBB, 0xCC, 0xDD];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType,
            streamId: 0x06,
            streamData,
            offset: 0x11223344);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal(frameType, frame.FrameType);
        Assert.Equal(0x06UL, frame.StreamId.Value);
        Assert.Equal(QuicStreamType.ClientInitiatedUnidirectional, frame.StreamType);
        Assert.True(frame.HasOffset);
        Assert.Equal(0x11223344UL, frame.Offset);
        Assert.True(frame.HasLength);
        Assert.Equal((ulong)streamData.Length, frame.Length);
        Assert.True(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));

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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStreamFrame_RejectsInvalidTypesAndOffsetMismatches()
    {
        Span<byte> destination = stackalloc byte[64];

        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x07, 0x04, 0, [0xAA], destination, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x08, 0x04, 1, [0xAA], destination, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x0F, 0x04, QuicVariableLengthInteger.MaxValue, [0xAA], destination, out _));
    }
}
