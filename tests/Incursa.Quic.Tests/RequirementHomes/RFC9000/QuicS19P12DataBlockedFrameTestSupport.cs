namespace Incursa.Quic.Tests;

internal static class QuicS19P12DataBlockedFrameTestSupport
{
    internal const byte DataBlockedFrameType = 0x14;

    internal static byte[] BuildDataBlockedFrame(ulong maximumData = 16)
        => QuicFrameTestData.BuildDataBlockedFrame(new QuicDataBlockedFrame(maximumData));

    internal static byte[] BuildDataBlockedFrameWithEncodedType(ReadOnlySpan<byte> encodedType)
    {
        List<byte> bytes = [.. encodedType.ToArray()];
        bytes.AddRange(EncodeVarint(16));
        return bytes.ToArray();
    }

    internal static byte[] BuildDataBlockedFrameWithEncodedMaximumData(ReadOnlySpan<byte> encodedMaximumData)
    {
        List<byte> bytes = [DataBlockedFrameType];
        bytes.AddRange(encodedMaximumData.ToArray());
        return bytes.ToArray();
    }

    internal static byte[] BuildDataBlockedFrameWithTrailingFrame(ulong maximumData = 16, byte trailingFrameType = 0x01)
    {
        byte[] frame = BuildDataBlockedFrame(maximumData);
        return [.. frame, trailingFrameType];
    }

    internal static byte[] EncodeVarint(ulong value)
    {
        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, destination, out int bytesWritten));
        return destination[..bytesWritten].ToArray();
    }

    internal static void AssertParses(byte[] encoded, ulong expectedMaximumData)
    {
        Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(
            encoded,
            out QuicDataBlockedFrame frame,
            out int bytesConsumed));

        Assert.Equal(expectedMaximumData, frame.MaximumData);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    internal static void AssertRejects(byte[] encoded)
    {
        Assert.False(QuicFrameCodec.TryParseDataBlockedFrame(encoded, out _, out _));
    }

    internal static void AssertFormats(QuicDataBlockedFrame frame, byte[] expected)
    {
        Span<byte> destination = stackalloc byte[16];

        Assert.True(QuicFrameCodec.TryFormatDataBlockedFrame(frame, destination, out int bytesWritten));
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
