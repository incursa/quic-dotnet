namespace Incursa.Quic;

/// <summary>
/// A parsed long-header-form packet view.
/// </summary>
public readonly ref struct QuicLongHeaderPacket
{
    private readonly byte headerControlBits;
    private readonly uint version;
    private readonly ReadOnlySpan<byte> destinationConnectionId;
    private readonly ReadOnlySpan<byte> sourceConnectionId;
    private readonly ReadOnlySpan<byte> versionSpecificData;

    internal QuicLongHeaderPacket(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> versionSpecificData)
    {
        this.headerControlBits = headerControlBits;
        this.version = version;
        this.destinationConnectionId = destinationConnectionId;
        this.sourceConnectionId = sourceConnectionId;
        this.versionSpecificData = versionSpecificData;
    }

    /// <summary>
    /// Gets the version-independent header form.
    /// </summary>
    public QuicHeaderForm HeaderForm => QuicHeaderForm.Long;

    /// <summary>
    /// Gets the seven non-form bits from the first byte.
    /// </summary>
    public byte HeaderControlBits => headerControlBits;

    /// <summary>
    /// Gets whether the fixed bit is set in byte 0.
    /// </summary>
    public bool FixedBit => (headerControlBits & 0x40) != 0;

    /// <summary>
    /// Gets the two-bit long packet type field from byte 0.
    /// </summary>
    public byte LongPacketTypeBits => (byte)((headerControlBits & 0x30) >> 4);

    /// <summary>
    /// Gets the two-bit packet number length field from byte 0.
    /// </summary>
    public byte PacketNumberLengthBits => (byte)(headerControlBits & 0x03);

    /// <summary>
    /// Gets the four type-specific bits from byte 0.
    /// </summary>
    public byte TypeSpecificBits => (byte)(headerControlBits & 0x0F);

    /// <summary>
    /// Gets the reserved bits from the type-specific bit field.
    /// </summary>
    public byte ReservedBits => (byte)((headerControlBits & 0x0C) >> 2);

    /// <summary>
    /// Gets the encoded QUIC version.
    /// </summary>
    public uint Version => version;

    /// <summary>
    /// Gets whether the version field is reserved for version negotiation.
    /// </summary>
    public bool IsVersionNegotiation => version == 0;

    /// <summary>
    /// Gets the encoded destination connection ID.
    /// </summary>
    public ReadOnlySpan<byte> DestinationConnectionId => destinationConnectionId;

    /// <summary>
    /// Gets the encoded destination connection ID length in bytes.
    /// </summary>
    public int DestinationConnectionIdLength => destinationConnectionId.Length;

    /// <summary>
    /// Gets the encoded source connection ID.
    /// </summary>
    public ReadOnlySpan<byte> SourceConnectionId => sourceConnectionId;

    /// <summary>
    /// Gets the encoded source connection ID length in bytes.
    /// </summary>
    public int SourceConnectionIdLength => sourceConnectionId.Length;

    /// <summary>
    /// Gets the trailing version-specific bytes.
    /// </summary>
    public ReadOnlySpan<byte> VersionSpecificData => versionSpecificData;
}
