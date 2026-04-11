namespace Incursa.Quic;

/// <summary>
/// A parsed short-header-form packet view with an opaque remainder.
/// </summary>
internal readonly ref struct QuicShortHeaderPacket
{
    private readonly byte headerControlBits;
    private readonly ReadOnlySpan<byte> remainder;

    internal QuicShortHeaderPacket(byte headerControlBits, ReadOnlySpan<byte> remainder)
    {
        this.headerControlBits = headerControlBits;
        this.remainder = remainder;
    }

    /// <summary>
    /// Gets the version-independent header form.
    /// </summary>
    internal QuicHeaderForm HeaderForm => QuicHeaderForm.Short;

    /// <summary>
    /// Gets the seven non-form bits from the first byte.
    /// </summary>
    internal byte HeaderControlBits => headerControlBits;

    /// <summary>
    /// Gets whether the fixed bit is set in byte 0.
    /// </summary>
    internal bool FixedBit => (headerControlBits & QuicPacketHeaderBits.FixedBitMask) != 0;

    /// <summary>
    /// Gets whether the spin bit is set in byte 0.
    /// </summary>
    internal bool SpinBit => (headerControlBits & QuicPacketHeaderBits.SpinBitMask) != 0;

    /// <summary>
    /// Gets the reserved bits from byte 0.
    /// </summary>
    internal byte ReservedBits => (byte)((headerControlBits & QuicPacketHeaderBits.ShortReservedBitsMask) >> QuicPacketHeaderBits.ShortReservedBitsShift);

    /// <summary>
    /// Gets whether the key phase bit is set in byte 0.
    /// </summary>
    internal bool KeyPhase => (headerControlBits & QuicPacketHeaderBits.KeyPhaseBitMask) != 0;

    /// <summary>
    /// Gets the packet number length bits from byte 0.
    /// </summary>
    internal byte PacketNumberLengthBits => (byte)(headerControlBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask);

    /// <summary>
    /// Gets the bytes after the first byte as an opaque remainder.
    /// </summary>
    internal ReadOnlySpan<byte> Remainder => remainder;
}

