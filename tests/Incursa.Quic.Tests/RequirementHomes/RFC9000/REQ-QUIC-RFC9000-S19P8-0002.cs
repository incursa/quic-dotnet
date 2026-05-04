namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0002")]
public sealed class REQ_QUIC_RFC9000_S19P8_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_UsesTheRemainderWhenLengthIsAbsent()
    {
        byte frameType = 0x08;
        byte[] streamData = [0x10, 0x20, 0x30];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType,
            streamId: 0x04,
            streamData);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.False(frame.HasOffset);
        Assert.Equal(0UL, frame.Offset);
        Assert.False(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.False(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(streamData.Length, frame.StreamDataLength);
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
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStreamFrame_RejectsOffsetFieldWhenOffBitIsClear()
    {
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryFormatStreamFrame(
            frameType: 0x08,
            streamId: 0x04,
            offset: 7,
            streamData: [0xAA],
            destination,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_AbsentOffsetStartsEmptyStreamAtZero()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x08,
            streamId: 0x04,
            streamData: []);

        Assert.False(frame.HasOffset);
        Assert.Equal(0UL, frame.Offset);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.True(frame.StreamData.IsEmpty);
    }
}
