namespace Incursa.Quic;

internal static class QuicStreamFrameBits
{
    internal const byte StreamFrameTypeMinimum = 0x08;
    internal const byte StreamFrameTypeMaximum = 0x0F;
    internal const byte OffsetBitMask = 0x04;
    internal const byte LengthBitMask = 0x02;
    internal const byte FinBitMask = 0x01;
}
