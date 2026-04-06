namespace Incursa.Quic;

internal static class QuicLongPacketTypeBits
{
    internal const byte Initial = 0x00;
    internal const byte ZeroRtt = 0x01;
    internal const byte Handshake = 0x02;
    internal const byte Retry = 0x03;
}
