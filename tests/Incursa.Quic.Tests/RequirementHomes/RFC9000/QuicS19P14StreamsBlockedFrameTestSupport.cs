namespace Incursa.Quic.Tests;

internal static class QuicS19P14StreamsBlockedFrameTestSupport
{
    internal const byte StreamsBlockedBidirectionalFrameType = 0x16;
    internal const byte StreamsBlockedUnidirectionalFrameType = 0x17;
    internal const ulong MaximumStreamLimit = 1UL << 60;

    internal static byte[] BuildStreamsBlockedFrame(bool isBidirectional = true, ulong maximumStreams = 16)
        => QuicFrameTestData.BuildStreamsBlockedFrame(new QuicStreamsBlockedFrame(isBidirectional, maximumStreams));

    internal static byte[] BuildStreamsBlockedFrameWithEncodedType(
        ReadOnlySpan<byte> encodedType,
        ulong maximumStreams = 16)
    {
        List<byte> bytes = [.. encodedType.ToArray()];
        bytes.AddRange(EncodeVarint(maximumStreams));
        return bytes.ToArray();
    }

    internal static byte[] BuildStreamsBlockedFrameWithEncodedMaximumStreams(
        bool isBidirectional,
        ReadOnlySpan<byte> encodedMaximumStreams)
    {
        List<byte> bytes =
        [
            isBidirectional
                ? StreamsBlockedBidirectionalFrameType
                : StreamsBlockedUnidirectionalFrameType
        ];
        bytes.AddRange(encodedMaximumStreams.ToArray());
        return bytes.ToArray();
    }

    internal static byte[] BuildStreamsBlockedFrameWithTrailingFrame(
        bool isBidirectional = true,
        ulong maximumStreams = 16,
        byte trailingFrameType = 0x01)
    {
        byte[] frame = BuildStreamsBlockedFrame(isBidirectional, maximumStreams);
        return [.. frame, trailingFrameType];
    }

    internal static byte[] EncodeVarint(ulong value)
    {
        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, destination, out int bytesWritten));
        return destination[..bytesWritten].ToArray();
    }

    internal static void AssertParses(byte[] encoded, bool expectedIsBidirectional, ulong expectedMaximumStreams)
    {
        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(
            encoded,
            out QuicStreamsBlockedFrame frame,
            out int bytesConsumed));

        Assert.Equal(expectedIsBidirectional, frame.IsBidirectional);
        Assert.Equal(expectedMaximumStreams, frame.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    internal static void AssertRejects(byte[] encoded)
    {
        Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out _, out _));
    }

    internal static void AssertFormats(QuicStreamsBlockedFrame frame, byte[] expected)
    {
        Span<byte> destination = stackalloc byte[16];

        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(frame, destination, out int bytesWritten));
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
