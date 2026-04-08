namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
public sealed class REQ_QUIC_RFC9000_S19P8_0019
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_AcceptsOffsetsThatExactlyReachTheStreamCeiling()
    {
        byte[] streamData = [0xAB];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x00,
            streamData,
            offset: QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.True(frame.HasLength);
        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, frame.Offset);
        Assert.Equal(1UL, frame.Length);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, frame.Offset + frame.Length);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_AcceptsOffsetsThatExactlyReachTheStreamCeilingWithoutALengthField()
    {
        byte[] streamData = [0xCD];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x00,
            streamData,
            offset: QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, frame.Offset);
        Assert.False(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, frame.Offset + (ulong)frame.StreamDataLength);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_AcceptsOffsetsAtTheStreamCeilingWhenLengthIsPresent()
    {
        byte[] streamData = [0xAA];
        ulong offset = QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length;
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x06,
            streamData,
            offset);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal((ulong)0x06, frame.StreamId.Value);
        Assert.True(frame.HasOffset);
        Assert.Equal(offset, frame.Offset);
        Assert.True(frame.HasLength);
        Assert.Equal((ulong)streamData.Length, frame.Length);
        Assert.True(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_AcceptsOffsetsAtTheStreamCeilingWhenLengthIsAbsent()
    {
        byte[] streamData = [0x10];
        ulong offset = QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length;
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x04,
            streamData,
            offset);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal((ulong)0x04, frame.StreamId.Value);
        Assert.True(frame.HasOffset);
        Assert.Equal(offset, frame.Offset);
        Assert.False(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.False(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(streamData.Length, frame.StreamDataLength);
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }
}
