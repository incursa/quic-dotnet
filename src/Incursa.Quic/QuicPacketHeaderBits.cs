namespace Incursa.Quic;

/// <summary>
/// Bit masks for the first byte of QUIC packets, based on the RFC 9000 header layouts.
/// </summary>
internal static class QuicPacketHeaderBits
{
    /// <summary>
    /// The top bit that selects long-header packets when set.
    /// </summary>
    internal const byte HeaderFormBitMask = 0x80;

    /// <summary>
    /// The complement of the header-form bit, leaving the seven non-form control bits.
    /// </summary>
    internal const byte HeaderControlBitsMask = 0x7F;

    /// <summary>
    /// The RFC 9000 fixed bit, which is always set on valid QUIC packets.
    /// </summary>
    internal const byte FixedBitMask = 0x40;

    /// <summary>
    /// The short-header spin bit.
    /// </summary>
    internal const byte SpinBitMask = 0x20;

    /// <summary>
    /// The two reserved bits in the short header.
    /// </summary>
    internal const byte ShortReservedBitsMask = 0x18;

    /// <summary>
    /// Shift used to expose the short-header reserved bits as a compact value.
    /// </summary>
    internal const int ShortReservedBitsShift = 3;

    /// <summary>
    /// The two packet-type bits carried in the long header.
    /// </summary>
    internal const byte LongPacketTypeBitsMask = 0x30;

    /// <summary>
    /// Shift used to expose the long-header packet type as a compact value.
    /// </summary>
    internal const int LongPacketTypeBitsShift = 4;

    /// <summary>
    /// The two reserved bits in the long header.
    /// </summary>
    internal const byte LongReservedBitsMask = 0x0C;

    /// <summary>
    /// Shift used to expose the long-header reserved bits as a compact value.
    /// </summary>
    internal const int LongReservedBitsShift = 2;

    /// <summary>
    /// The key phase bit in a short header.
    /// </summary>
    internal const byte KeyPhaseBitMask = 0x04;

    /// <summary>
    /// The packet-number-length bits in the packet header.
    /// </summary>
    internal const byte PacketNumberLengthBitsMask = 0x03;

    /// <summary>
    /// The low nibble of the first byte, exposed as a convenience view for type-specific parsing.
    /// </summary>
    internal const byte TypeSpecificBitsMask = 0x0F;
}
