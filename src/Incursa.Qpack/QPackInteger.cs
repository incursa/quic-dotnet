using System.Buffers;

namespace Incursa.Qpack;

/// <summary>
/// Encodes and decodes RFC 9204 prefixed integers.
/// </summary>
public static class QPackInteger
{
    private const int MaxPrefixBitCount = 8;
    private const int MaxContinuationShift = 63;
    private const byte ContinuationThreshold = 0x80;
    private const byte ContinuationValueMask = 0x7F;
    private const byte ContinuationFlag = 0x80;
    private const int ContinuationShift = 7;

    /// <summary>
    /// The largest QPACK integer value required by RFC 9204.
    /// </summary>
    public const ulong MaxValue = 0x3FFF_FFFF_FFFF_FFFFUL;

    /// <summary>
    /// Encodes a prefixed integer.
    /// </summary>
    public static byte[] Encode(ulong value, int prefixBitCount, byte prefixBits = 0)
    {
        ArrayBufferWriter<byte> writer = new();
        Write(writer, value, prefixBitCount, prefixBits);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Decodes a prefixed integer from the start of <paramref name="source" />.
    /// </summary>
    public static ulong Decode(ReadOnlySpan<byte> source, int prefixBitCount, out int bytesConsumed)
    {
        if (!TryDecode(source, prefixBitCount, out ulong value, out bytesConsumed))
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK prefixed integer is malformed.");
        }

        return value;
    }

    internal static void Write(IBufferWriter<byte> writer, ulong value, int prefixBitCount, byte prefixBits = 0)
    {
        ValidatePrefixBitCount(prefixBitCount);
        if (value > MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        byte mask = GetPrefixMask(prefixBitCount);
        Span<byte> first = writer.GetSpan(1);
        if (value < mask)
        {
            first[0] = (byte)(prefixBits | value);
            writer.Advance(1);
            return;
        }

        first[0] = (byte)(prefixBits | mask);
        writer.Advance(1);

        value -= mask;
        while (value >= ContinuationThreshold)
        {
            Span<byte> continuation = writer.GetSpan(1);
            continuation[0] = (byte)((value & ContinuationValueMask) | ContinuationFlag);
            writer.Advance(1);
            value >>= ContinuationShift;
        }

        Span<byte> terminal = writer.GetSpan(1);
        terminal[0] = (byte)value;
        writer.Advance(1);
    }

    internal static bool TryDecode(ReadOnlySpan<byte> source, int prefixBitCount, out ulong value, out int bytesConsumed)
    {
        ValidatePrefixBitCount(prefixBitCount);
        value = default;
        bytesConsumed = default;

        if (source.IsEmpty)
        {
            return false;
        }

        ulong mask = GetPrefixMask(prefixBitCount);
        value = source[0] & mask;
        bytesConsumed = 1;
        if (value < mask)
        {
            return true;
        }

        int shift = 0;
        while (bytesConsumed < source.Length)
        {
            byte next = source[bytesConsumed++];
            ulong segment = (ulong)(next & ContinuationValueMask);
            if (shift >= MaxContinuationShift || (segment << shift) > MaxValue - value)
            {
                return false;
            }

            value += segment << shift;
            if ((next & ContinuationFlag) == 0)
            {
                return value <= MaxValue;
            }

            shift += ContinuationShift;
        }

        return false;
    }

    private static byte GetPrefixMask(int prefixBitCount)
    {
        return prefixBitCount == MaxPrefixBitCount
            ? byte.MaxValue
            : (byte)((1 << prefixBitCount) - 1);
    }

    private static void ValidatePrefixBitCount(int prefixBitCount)
    {
        if (prefixBitCount is < 1 or > MaxPrefixBitCount)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixBitCount));
        }
    }
}
