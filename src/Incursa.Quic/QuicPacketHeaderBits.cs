namespace Incursa.Quic;

internal static class QuicPacketHeaderBits
{
    internal const byte HeaderFormBitMask = 0x80;
    internal const byte HeaderControlBitsMask = 0x7F;
    internal const byte FixedBitMask = 0x40;
    internal const byte SpinBitMask = 0x20;
    internal const byte ShortReservedBitsMask = 0x18;
    internal const int ShortReservedBitsShift = 3;
    internal const byte LongPacketTypeBitsMask = 0x30;
    internal const int LongPacketTypeBitsShift = 4;
    internal const byte LongReservedBitsMask = 0x0C;
    internal const int LongReservedBitsShift = 2;
    internal const byte KeyPhaseBitMask = 0x04;
    internal const byte PacketNumberLengthBitsMask = 0x03;
    internal const byte TypeSpecificBitsMask = 0x0F;
}
