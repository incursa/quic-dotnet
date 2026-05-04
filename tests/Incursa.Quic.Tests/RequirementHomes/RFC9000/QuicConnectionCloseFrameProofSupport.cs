namespace Incursa.Quic.Tests;

internal static class QuicConnectionCloseFrameProofSupport
{
    internal static byte[] BuildTransportClose(
        ulong errorCode = 0x1234,
        ulong triggeringFrameType = 0x02,
        byte[]? reasonPhrase = null)
    {
        byte[] reason = reasonPhrase ?? [0x6F, 0x6B];
        return QuicFrameTestData.BuildConnectionCloseFrame(
            new QuicConnectionCloseFrame(errorCode, triggeringFrameType, reason));
    }

    internal static byte[] BuildApplicationClose(
        ulong errorCode = 0x1234,
        byte[]? reasonPhrase = null)
    {
        byte[] reason = reasonPhrase ?? [0x61, 0x70, 0x70];
        return QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(errorCode, reason));
    }

    internal static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }
}
