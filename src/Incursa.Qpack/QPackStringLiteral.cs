using System.Buffers;
using System.Text;

namespace Incursa.Qpack;

internal static class QPackStringLiteral
{
    private const int MinPrefixBitCount = 2;
    private const int MaxPrefixBitCount = 8;

    private static readonly Encoding HeaderTextEncoding = Encoding.Latin1;

    public static void Write(IBufferWriter<byte> writer, string value, int prefixBitCount, byte prefixBits = 0)
    {
        ArgumentNullException.ThrowIfNull(value);
        ValidatePrefixBitCount(prefixBitCount);
        byte[] bytes = HeaderTextEncoding.GetBytes(value);
        QPackInteger.Write(writer, checked((ulong)bytes.Length), prefixBitCount - 1, prefixBits);

        Span<byte> destination = writer.GetSpan(bytes.Length);
        bytes.CopyTo(destination);
        writer.Advance(bytes.Length);
    }

    public static string Read(ReadOnlySpan<byte> source, int prefixBitCount, out int bytesConsumed)
    {
        ValidatePrefixBitCount(prefixBitCount);
        if (source.IsEmpty)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK string literal is truncated.");
        }

        int huffmanBit = 1 << (prefixBitCount - 1);
        bool huffmanEncoded = (source[0] & huffmanBit) != 0;
        ulong length = QPackInteger.Decode(source, prefixBitCount - 1, out int lengthBytes);
        if (length > (ulong)(source.Length - lengthBytes) || length > int.MaxValue)
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK string literal length is invalid.");
        }

        bytesConsumed = checked(lengthBytes + (int)length);
        ReadOnlySpan<byte> encodedString = source.Slice(lengthBytes, (int)length);
        return huffmanEncoded
            ? QPackHuffman.Decode(encodedString, QPackErrorCode.DecompressionFailed)
            : HeaderTextEncoding.GetString(encodedString);
    }

    private static void ValidatePrefixBitCount(int prefixBitCount)
    {
        if (prefixBitCount is < MinPrefixBitCount or > MaxPrefixBitCount)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixBitCount));
        }
    }
}
