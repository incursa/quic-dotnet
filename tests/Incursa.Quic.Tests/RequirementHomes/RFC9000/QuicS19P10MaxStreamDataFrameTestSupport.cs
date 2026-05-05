namespace Incursa.Quic.Tests;

internal static class QuicS19P10MaxStreamDataFrameTestSupport
{
    internal const byte MaxStreamDataFrameType = 0x11;

    internal static byte[] BuildMaxStreamDataFrame(ulong streamId = 1, ulong maximumStreamData = 16)
        => QuicFrameTestData.BuildMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, maximumStreamData));

    internal static byte[] BuildMaxStreamDataFrameWithEncodedType(ReadOnlySpan<byte> encodedType)
    {
        List<byte> bytes = [.. encodedType.ToArray()];
        bytes.AddRange(EncodeVarint(1));
        bytes.AddRange(EncodeVarint(16));
        return bytes.ToArray();
    }

    internal static byte[] BuildMaxStreamDataFrameWithEncodedStreamId(ReadOnlySpan<byte> encodedStreamId)
    {
        List<byte> bytes = [MaxStreamDataFrameType];
        bytes.AddRange(encodedStreamId.ToArray());
        bytes.AddRange(EncodeVarint(16));
        return bytes.ToArray();
    }

    internal static byte[] BuildMaxStreamDataFrameWithEncodedMaximumStreamData(ReadOnlySpan<byte> encodedMaximumStreamData)
    {
        List<byte> bytes = [MaxStreamDataFrameType];
        bytes.AddRange(EncodeVarint(1));
        bytes.AddRange(encodedMaximumStreamData.ToArray());
        return bytes.ToArray();
    }

    internal static byte[] BuildMaxStreamDataFrameWithTrailingFrame(
        ulong streamId = 1,
        ulong maximumStreamData = 16,
        byte trailingFrameType = 0x01)
    {
        byte[] frame = BuildMaxStreamDataFrame(streamId, maximumStreamData);
        return [.. frame, trailingFrameType];
    }

    internal static byte[] EncodeVarint(ulong value)
    {
        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, destination, out int bytesWritten));
        return destination[..bytesWritten].ToArray();
    }

    internal static void AssertParses(byte[] encoded, ulong expectedStreamId, ulong expectedMaximumStreamData)
    {
        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(
            encoded,
            out QuicMaxStreamDataFrame frame,
            out int bytesConsumed));

        Assert.Equal(expectedStreamId, frame.StreamId);
        Assert.Equal(expectedMaximumStreamData, frame.MaximumStreamData);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    internal static void AssertRejects(byte[] encoded)
    {
        Assert.False(QuicFrameCodec.TryParseMaxStreamDataFrame(encoded, out _, out _));
    }

    internal static void AssertFormats(QuicMaxStreamDataFrame frame, byte[] expected)
    {
        Span<byte> destination = stackalloc byte[32];

        Assert.True(QuicFrameCodec.TryFormatMaxStreamDataFrame(frame, destination, out int bytesWritten));
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
