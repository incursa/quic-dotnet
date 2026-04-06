using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// Parses and formats QUIC variable-length integers.
/// </summary>
public static class QuicVariableLengthInteger
{
    /// <summary>
    /// QUIC varints use the top two bits of the first byte to encode the length.
    /// </summary>
    private const int LengthPrefixBitCount = 6;

    /// <summary>
    /// The first byte carries six payload bits after the length prefix.
    /// </summary>
    private const byte LengthValueMask = 0x3F;

    /// <summary>
    /// The two-byte varint prefix value.
    /// </summary>
    private const byte TwoByteLengthPrefix = 0x40;

    /// <summary>
    /// The four-byte varint prefix value.
    /// </summary>
    private const byte FourByteLengthPrefix = 0x80;

    /// <summary>
    /// The eight-byte varint prefix value.
    /// </summary>
    private const byte EightByteLengthPrefix = 0xC0;

    /// <summary>
    /// The encoded length of a one-byte varint.
    /// </summary>
    private const int OneByteEncodedLength = sizeof(byte);

    /// <summary>
    /// The encoded length of a two-byte varint.
    /// </summary>
    private const int TwoByteEncodedLength = sizeof(ushort);

    /// <summary>
    /// The encoded length of a four-byte varint.
    /// </summary>
    private const int FourByteEncodedLength = sizeof(uint);

    /// <summary>
    /// The encoded length of an eight-byte varint.
    /// </summary>
    private const int EightByteEncodedLength = sizeof(ulong);

    private static readonly int[] EncodedLengths = [OneByteEncodedLength, TwoByteEncodedLength, FourByteEncodedLength, EightByteEncodedLength];

    /// <summary>
    /// The largest value that fits in the one-byte encoding.
    /// </summary>
    private const ulong MaxOneByteValue = 0x3F;

    /// <summary>
    /// The largest value that fits in the two-byte encoding.
    /// </summary>
    private const ulong MaxTwoByteValue = 0x3FFF;

    /// <summary>
    /// The largest value that fits in the four-byte encoding.
    /// </summary>
    private const ulong MaxFourByteValue = 0x3FFF_FFFF;

    /// <summary>
    /// The largest value representable by the QUIC variable-length integer encoding.
    /// RFC 9000 uses 62 payload bits after the length prefix.
    /// </summary>
    public const ulong MaxValue = 0x3FFF_FFFF_FFFF_FFFFUL;

    /// <summary>
    /// The maximum encoded length of a QUIC variable-length integer.
    /// </summary>
    internal const int MaxEncodedLength = EightByteEncodedLength;

    /// <summary>
    /// Parses a QUIC variable-length integer from the start of a byte span.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> encoded, out ulong value, out int bytesConsumed)
    {
        value = default;
        bytesConsumed = default;

        if (encoded.IsEmpty)
        {
            return false;
        }

        int encodedLengthPrefix = encoded[0] >> LengthPrefixBitCount;
        if ((uint)encodedLengthPrefix >= (uint)EncodedLengths.Length)
        {
            return false;
        }

        int length = EncodedLengths[encodedLengthPrefix];
        if (encoded.Length < length)
        {
            return false;
        }

        value = length switch
        {
            OneByteEncodedLength => (ulong)(encoded[0] & LengthValueMask),
            TwoByteEncodedLength => (ulong)(BinaryPrimitives.ReadUInt16BigEndian(encoded) & (ushort)MaxTwoByteValue),
            FourByteEncodedLength => (ulong)(BinaryPrimitives.ReadUInt32BigEndian(encoded) & (uint)MaxFourByteValue),
            EightByteEncodedLength => BinaryPrimitives.ReadUInt64BigEndian(encoded) & MaxValue,
            _ => default
        };

        bytesConsumed = length;
        return true;
    }

    /// <summary>
    /// Formats a QUIC variable-length integer using the shortest possible encoding.
    /// </summary>
    public static bool TryFormat(ulong value, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryGetEncodedLength(value, out int length) || destination.Length < length)
        {
            return false;
        }

        switch (length)
        {
            case OneByteEncodedLength:
                destination[0] = (byte)value;
                break;
            case TwoByteEncodedLength:
                BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)value);
                destination[0] |= TwoByteLengthPrefix;
                break;
            case FourByteEncodedLength:
                BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)value);
                destination[0] |= FourByteLengthPrefix;
                break;
            case EightByteEncodedLength:
                BinaryPrimitives.WriteUInt64BigEndian(destination, value);
                destination[0] |= EightByteLengthPrefix;
                break;
            default:
                return false;
        }

        bytesWritten = length;
        return true;
    }

    private static bool TryGetEncodedLength(ulong value, out int length)
    {
        if (value <= MaxOneByteValue)
        {
            length = OneByteEncodedLength;
            return true;
        }

        if (value <= MaxTwoByteValue)
        {
            length = TwoByteEncodedLength;
            return true;
        }

        if (value <= MaxFourByteValue)
        {
            length = FourByteEncodedLength;
            return true;
        }

        if (value <= MaxValue)
        {
            length = EightByteEncodedLength;
            return true;
        }

        length = default;
        return false;
    }
}
