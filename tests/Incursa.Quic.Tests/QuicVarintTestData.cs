namespace Incursa.Quic.Tests;

internal static class QuicVarintTestData
{
    public static byte[] EncodeMinimal(ulong value)
    {
        byte[] buffer = new byte[8];
        if (!QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten))
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        return buffer[..bytesWritten];
    }

    public static byte[] EncodeWithLength(ulong value, int encodedLength)
    {
        if (encodedLength is not (1 or 2 or 4 or 8))
        {
            throw new ArgumentOutOfRangeException(nameof(encodedLength));
        }

        byte[] encoded = new byte[encodedLength];
        switch (encodedLength)
        {
            case 1:
                encoded[0] = (byte)value;
                break;
            case 2:
                encoded[0] = (byte)(0x40 | ((value >> 8) & 0x3F));
                encoded[1] = (byte)value;
                break;
            case 4:
                encoded[0] = (byte)(0x80 | ((value >> 24) & 0x3F));
                encoded[1] = (byte)(value >> 16);
                encoded[2] = (byte)(value >> 8);
                encoded[3] = (byte)value;
                break;
            case 8:
                encoded[0] = (byte)(0xC0 | ((value >> 56) & 0x3F));
                encoded[1] = (byte)(value >> 48);
                encoded[2] = (byte)(value >> 40);
                encoded[3] = (byte)(value >> 32);
                encoded[4] = (byte)(value >> 24);
                encoded[5] = (byte)(value >> 16);
                encoded[6] = (byte)(value >> 8);
                encoded[7] = (byte)value;
                break;
        }

        return encoded;
    }
}
