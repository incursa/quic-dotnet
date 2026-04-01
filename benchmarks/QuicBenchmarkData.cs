namespace Incursa.Quic.Benchmarks;

internal static class QuicBenchmarkData
{
    public static byte[] EncodeVarInt(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        if (!QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to encode a representative QUIC varint.");
        }

        return buffer[..bytesWritten].ToArray();
    }

    public static byte[] BuildStreamFrame(
        byte frameType,
        ulong streamId,
        bool includeOffset,
        ulong offset,
        bool includeLength,
        ReadOnlySpan<byte> streamData)
    {
        List<byte> packet = new(1 + 8 + 8 + 8 + streamData.Length)
        {
            frameType,
        };

        packet.AddRange(EncodeVarInt(streamId));

        if (includeOffset)
        {
            packet.AddRange(EncodeVarInt(offset));
        }

        if (includeLength)
        {
            packet.AddRange(EncodeVarInt((ulong)streamData.Length));
        }

        packet.AddRange(streamData.ToArray());
        return packet.ToArray();
    }

    public static byte[] BuildCryptoFrame(ulong offset, ReadOnlySpan<byte> cryptoData)
    {
        List<byte> packet = new(1 + 8 + 8 + cryptoData.Length)
        {
            0x06,
        };

        packet.AddRange(EncodeVarInt(offset));
        packet.AddRange(EncodeVarInt((ulong)cryptoData.Length));
        packet.AddRange(cryptoData.ToArray());
        return packet.ToArray();
    }
}
