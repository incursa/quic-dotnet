namespace Incursa.Quic;

/// <summary>
/// Parses and formats QUIC variable-length integers.
/// </summary>
public static class QuicVariableLengthInteger
{
    /// <summary>
    /// The largest value representable by the QUIC variable-length integer encoding.
    /// </summary>
    public const ulong MaxValue = 0x3FFF_FFFF_FFFF_FFFFUL;

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

        int length = 1 << (encoded[0] >> 6);
        if (encoded.Length < length)
        {
            return false;
        }

        value = length switch
        {
            1 => (ulong)(encoded[0] & 0x3F),
            2 => ((ulong)(encoded[0] & 0x3F) << 8)
                | encoded[1],
            4 => ((ulong)(encoded[0] & 0x3F) << 24)
                | ((ulong)encoded[1] << 16)
                | ((ulong)encoded[2] << 8)
                | encoded[3],
            8 => ((ulong)(encoded[0] & 0x3F) << 56)
                | ((ulong)encoded[1] << 48)
                | ((ulong)encoded[2] << 40)
                | ((ulong)encoded[3] << 32)
                | ((ulong)encoded[4] << 24)
                | ((ulong)encoded[5] << 16)
                | ((ulong)encoded[6] << 8)
                | encoded[7],
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
            case 1:
                destination[0] = (byte)value;
                break;
            case 2:
                destination[0] = (byte)(0x40 | ((value >> 8) & 0x3F));
                destination[1] = (byte)value;
                break;
            case 4:
                destination[0] = (byte)(0x80 | ((value >> 24) & 0x3F));
                destination[1] = (byte)(value >> 16);
                destination[2] = (byte)(value >> 8);
                destination[3] = (byte)value;
                break;
            case 8:
                destination[0] = (byte)(0xC0 | ((value >> 56) & 0x3F));
                destination[1] = (byte)(value >> 48);
                destination[2] = (byte)(value >> 40);
                destination[3] = (byte)(value >> 32);
                destination[4] = (byte)(value >> 24);
                destination[5] = (byte)(value >> 16);
                destination[6] = (byte)(value >> 8);
                destination[7] = (byte)value;
                break;
            default:
                return false;
        }

        bytesWritten = length;
        return true;
    }

    private static bool TryGetEncodedLength(ulong value, out int length)
    {
        if (value <= 0x3F)
        {
            length = 1;
            return true;
        }

        if (value <= 0x3FFF)
        {
            length = 2;
            return true;
        }

        if (value <= 0x3FFF_FFFF)
        {
            length = 4;
            return true;
        }

        if (value <= MaxValue)
        {
            length = 8;
            return true;
        }

        length = default;
        return false;
    }
}
