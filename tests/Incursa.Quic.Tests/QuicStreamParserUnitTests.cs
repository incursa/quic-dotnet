namespace Incursa.Quic.Tests;

public sealed class QuicStreamParserUnitTests
{
    [Fact]
    public void TryParseStreamIdentifier_ParsesMinimalTwoByteIdentifier()
    {
        byte[] encoded = QuicVarintTestData.EncodeMinimal(0x1234);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
        Assert.Equal(0x1234UL, streamId.Value);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    public void TryParseStreamIdentifier_RejectsTruncatedVarintShape()
    {
        byte[] encoded = [0x40];

        Assert.False(QuicStreamParser.TryParseStreamIdentifier(encoded, out _, out int bytesConsumed));
        Assert.Equal(0, bytesConsumed);
    }

    [Theory]
    [InlineData((byte)0x08)]
    [InlineData((byte)0x09)]
    [InlineData((byte)0x0C)]
    [InlineData((byte)0x0D)]
    public void TryParseStreamFrame_ParsesFramesWithoutLengthAndConsumesTheRemainder(byte frameType)
    {
        ulong streamId = 0x1234;
        bool hasOffset = (frameType & QuicStreamFrameBits.OffsetBitMask) != 0;
        bool isFin = (frameType & QuicStreamFrameBits.FinBitMask) != 0;
        ulong offset = hasOffset ? 0x40UL : 0UL;
        byte[] payload = [0x11, 0x22, 0x33];
        byte[] frame = QuicStreamTestData.BuildStreamFrame(frameType, streamId, payload, offset);
        byte[] packetPayload = [..frame, 0xDE, 0xAD];
        byte[] expectedStreamData = [..payload, 0xDE, 0xAD];

        Assert.True(QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame parsed));
        Assert.Equal(frameType, parsed.FrameType);
        Assert.Equal(streamId, parsed.StreamId.Value);
        Assert.Equal(hasOffset, parsed.HasOffset);
        Assert.Equal(offset, parsed.Offset);
        Assert.False(parsed.HasLength);
        Assert.Equal(0UL, parsed.Length);
        Assert.Equal(isFin, parsed.IsFin);
        Assert.Equal(expectedStreamData.Length, parsed.StreamDataLength);
        Assert.True(parsed.StreamData.SequenceEqual(expectedStreamData));
        Assert.Equal(packetPayload.Length, parsed.ConsumedLength);
    }

    [Theory]
    [InlineData((byte)0x0A)]
    [InlineData((byte)0x0B)]
    [InlineData((byte)0x0E)]
    [InlineData((byte)0x0F)]
    public void TryParseStreamFrame_ParsesFramesWithLengthAndStopsAtTheDeclaredPayload(byte frameType)
    {
        ulong streamId = 0x1234;
        bool hasOffset = (frameType & QuicStreamFrameBits.OffsetBitMask) != 0;
        bool isFin = (frameType & QuicStreamFrameBits.FinBitMask) != 0;
        ulong offset = hasOffset ? 0x40UL : 0UL;
        byte[] payload = [0x21, 0x22, 0x23];
        byte[] frame = QuicStreamTestData.BuildStreamFrame(frameType, streamId, payload, offset);
        byte[] packetPayload = [..frame, 0xDE, 0xAD];

        Assert.True(QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame parsed));
        Assert.Equal(frameType, parsed.FrameType);
        Assert.Equal(streamId, parsed.StreamId.Value);
        Assert.Equal(hasOffset, parsed.HasOffset);
        Assert.Equal(offset, parsed.Offset);
        Assert.True(parsed.HasLength);
        Assert.Equal((ulong)payload.Length, parsed.Length);
        Assert.Equal(isFin, parsed.IsFin);
        Assert.Equal(payload.Length, parsed.StreamDataLength);
        Assert.True(parsed.StreamData.SequenceEqual(payload));
        Assert.Equal(frame.Length, parsed.ConsumedLength);
    }

    [Fact]
    public void TryParseStreamFrame_RejectsTruncatedDeclaredPayload()
    {
        byte[] frame = QuicStreamTestData.BuildStreamFrame(0x0A, 0x1234, [0x21, 0x22, 0x23]);

        Assert.False(QuicStreamParser.TryParseStreamFrame(frame[..^1], out _));
    }

    [Fact]
    public void TryParseStreamFrame_RejectsMalformedFrameTypeVarintShape()
    {
        byte[] packetPayload = QuicStreamTestData.BuildStreamFrameWithEncodedType(0x08, 2, 0x1234, [0x21, 0x22, 0x23]);

        Assert.False(QuicStreamParser.TryParseStreamFrame(packetPayload, out _));
    }

    [Fact]
    public void TryParseStreamFrame_RejectsTruncatedOffsetVarintShape()
    {
        byte[] packetPayload =
        [
            ..QuicVarintTestData.EncodeMinimal(0x0C),
            ..QuicVarintTestData.EncodeMinimal(0x1234),
            0x40
        ];

        Assert.False(QuicStreamParser.TryParseStreamFrame(packetPayload, out _));
    }
}
