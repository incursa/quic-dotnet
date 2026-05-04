namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
public sealed class REQ_QUIC_RFC9000_S19P8_0004
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
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_AcceptsOffsetsThatExactlyReachTheStreamCeilingWithoutALengthField()
    {
        byte[] streamData = [0xCD];
        ulong offset = QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length;
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x00,
            streamData,
            offset);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.Equal(offset, frame.Offset);
        Assert.False(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.False(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(streamData.Length, frame.StreamDataLength);
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_TreatsAppendedBytesAsDataWhenLenBitIsClear()
    {
        byte[] packet = [0x08, 0x00, 0x02, 0xAA, 0xBB];

        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.ParsePacket(packet);

        Assert.False(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.True(packet.AsSpan(2).SequenceEqual(frame.StreamData));
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_ConsumesNoDataAtEndWhenLenBitIsClear()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x08,
            streamId: 0x00,
            streamData: []);

        Assert.False(frame.HasLength);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.Equal(2, frame.ConsumedLength);
    }
}
