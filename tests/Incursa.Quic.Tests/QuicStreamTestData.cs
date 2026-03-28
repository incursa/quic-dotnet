namespace Incursa.Quic.Tests;

internal static class QuicStreamTestData
{
    public static byte[] BuildStreamIdentifier(ulong value)
    {
        return QuicVarintTestData.EncodeMinimal(value);
    }

    public static byte[] BuildStreamFrame(
        byte frameType,
        ulong streamId,
        ReadOnlySpan<byte> streamData,
        ulong offset = 0)
    {
        bool hasOffset = (frameType & 0x04) != 0;
        bool hasLength = (frameType & 0x02) != 0;

        byte[] frameTypeBytes = QuicVarintTestData.EncodeMinimal(frameType);
        byte[] streamIdBytes = QuicVarintTestData.EncodeMinimal(streamId);
        byte[] offsetBytes = hasOffset ? QuicVarintTestData.EncodeMinimal(offset) : [];
        byte[] lengthBytes = hasLength ? QuicVarintTestData.EncodeMinimal((ulong)streamData.Length) : [];

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

    public static byte[] BuildStreamFrameWithEncodedType(
        byte frameType,
        int encodedLength,
        ulong streamId,
        ReadOnlySpan<byte> streamData,
        ulong offset = 0)
    {
        bool hasOffset = (frameType & 0x04) != 0;
        bool hasLength = (frameType & 0x02) != 0;

        byte[] frameTypeBytes = QuicVarintTestData.EncodeWithLength(frameType, encodedLength);
        byte[] streamIdBytes = QuicVarintTestData.EncodeMinimal(streamId);
        byte[] offsetBytes = hasOffset ? QuicVarintTestData.EncodeMinimal(offset) : [];
        byte[] lengthBytes = hasLength ? QuicVarintTestData.EncodeMinimal((ulong)streamData.Length) : [];

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
