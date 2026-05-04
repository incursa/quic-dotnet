namespace Incursa.Quic.Tests;

internal static class QuicS19P8StreamFrameTestSupport
{
    internal static QuicStreamFrame Parse(byte frameType, ulong streamId, ReadOnlySpan<byte> streamData, ulong offset = 0)
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(frameType, streamId, streamData, offset);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal(packet.Length, frame.ConsumedLength);
        return frame;
    }

    internal static QuicStreamFrame ParsePacket(byte[] packet)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        return frame;
    }

    internal static void AssertRejects(byte[] packet)
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame(packet, out _));
    }

    internal static void AssertRoundTrips(byte[] packet, QuicStreamFrame frame)
    {
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

    internal static byte[] BuildStreamFrameWithDeclaredLength(
        byte frameType,
        ulong streamId,
        ulong declaredLength,
        ReadOnlySpan<byte> streamData,
        ulong offset = 0)
    {
        bool hasOffset = (frameType & QuicStreamFrameBits.OffsetBitMask) != 0;
        bool hasLength = (frameType & QuicStreamFrameBits.LengthBitMask) != 0;
        Assert.True(hasLength);

        byte[] frameTypeBytes = QuicVarintTestData.EncodeMinimal(frameType);
        byte[] streamIdBytes = QuicVarintTestData.EncodeMinimal(streamId);
        byte[] offsetBytes = hasOffset ? QuicVarintTestData.EncodeMinimal(offset) : [];
        byte[] lengthBytes = QuicVarintTestData.EncodeMinimal(declaredLength);

        byte[] frame = new byte[
            frameTypeBytes.Length
            + streamIdBytes.Length
            + offsetBytes.Length
            + lengthBytes.Length
            + streamData.Length];

        int index = 0;
        frameTypeBytes.CopyTo(frame.AsSpan(index));
        index += frameTypeBytes.Length;
        streamIdBytes.CopyTo(frame.AsSpan(index));
        index += streamIdBytes.Length;
        offsetBytes.CopyTo(frame.AsSpan(index));
        index += offsetBytes.Length;
        lengthBytes.CopyTo(frame.AsSpan(index));
        index += lengthBytes.Length;
        streamData.CopyTo(frame.AsSpan(index));

        return frame;
    }
}
