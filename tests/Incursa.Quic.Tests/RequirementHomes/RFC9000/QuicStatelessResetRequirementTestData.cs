namespace Incursa.Quic.Tests;

internal static class QuicStatelessResetRequirementTestData
{
    public static byte[] CreateBytes(int length, byte start)
    {
        byte[] bytes = new byte[length];

        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(start + index);
        }

        return bytes;
    }

    public static byte[] CreateConnectionId(byte start = 0x10, int length = 4)
    {
        return CreateBytes(length, start);
    }

    public static byte[] CreateSecret(byte start = 0x90, int length = 8)
    {
        return CreateBytes(length, start);
    }

    public static byte[] CreateToken(byte start = 0x20)
    {
        return CreateBytes(QuicStatelessReset.StatelessResetTokenLength, start);
    }

    public static byte[] FormatDatagram(ReadOnlySpan<byte> token, int datagramLength = QuicStatelessReset.MinimumDatagramLength)
    {
        byte[] datagram = new byte[datagramLength];

        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(token, datagramLength, datagram, out int bytesWritten));
        Assert.Equal(datagramLength, bytesWritten);

        return datagram;
    }

    public static void AssertShortHeaderLayout(ReadOnlySpan<byte> datagram)
    {
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(datagram));
        Assert.Equal(0, datagram[0] & 0x80);
        Assert.NotEqual(0, datagram[0] & 0x40);
    }

    public static void AssertTailTokenMatches(ReadOnlySpan<byte> datagram, ReadOnlySpan<byte> token)
    {
        Assert.True(token.SequenceEqual(datagram[^token.Length..]));
    }
}
