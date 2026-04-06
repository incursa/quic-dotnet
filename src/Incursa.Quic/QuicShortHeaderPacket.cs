namespace Incursa.Quic;

/// <summary>
/// A parsed short-header-form packet view with an opaque remainder.
/// </summary>
public readonly ref struct QuicShortHeaderPacket
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
    public QuicHeaderForm HeaderForm => QuicHeaderForm.Short;

    /// <summary>
    /// Gets the seven non-form bits from the first byte.
    /// </summary>
    public byte HeaderControlBits => headerControlBits;

    /// <summary>
    /// Gets whether the fixed bit is set in byte 0.
    /// </summary>
    public bool FixedBit => (headerControlBits & QuicPacketHeaderBits.FixedBitMask) != 0;

    /// <summary>
    /// Gets whether the spin bit is set in byte 0.
    /// </summary>
    public bool SpinBit => (headerControlBits & QuicPacketHeaderBits.SpinBitMask) != 0;

    /// <summary>
    /// Gets the reserved bits from byte 0.
    /// </summary>
    public byte ReservedBits => (byte)((headerControlBits & QuicPacketHeaderBits.ShortReservedBitsMask) >> QuicPacketHeaderBits.ShortReservedBitsShift);

    /// <summary>
    /// Gets whether the key phase bit is set in byte 0.
    /// </summary>
    public bool KeyPhase => (headerControlBits & QuicPacketHeaderBits.KeyPhaseBitMask) != 0;

    /// <summary>
    /// Gets the packet number length bits from byte 0.
    /// </summary>
    public byte PacketNumberLengthBits => (byte)(headerControlBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask);

    /// <summary>
    /// Gets the bytes after the first byte as an opaque remainder.
    /// </summary>
    public ReadOnlySpan<byte> Remainder => remainder;
}
