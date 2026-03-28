using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// A parsed Version Negotiation packet view.
/// </summary>
public readonly ref struct QuicVersionNegotiationPacket
{
    private readonly byte headerControlBits;
    private readonly ReadOnlySpan<byte> destinationConnectionId;
    private readonly ReadOnlySpan<byte> sourceConnectionId;
    private readonly ReadOnlySpan<byte> supportedVersionBytes;

    internal QuicVersionNegotiationPacket(
        byte headerControlBits,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> supportedVersionBytes)
    {
        this.headerControlBits = headerControlBits;
        this.destinationConnectionId = destinationConnectionId;
        this.sourceConnectionId = sourceConnectionId;
        this.supportedVersionBytes = supportedVersionBytes;
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
    /// Gets the reserved Version value for version negotiation.
    /// </summary>
    public uint Version => 0;

    /// <summary>
    /// Gets whether this packet is a Version Negotiation packet.
    /// </summary>
    public bool IsVersionNegotiation => true;

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
    /// Gets the supported-version bytes as encoded on the wire.
    /// </summary>
    public ReadOnlySpan<byte> SupportedVersionBytes => supportedVersionBytes;

    /// <summary>
    /// Gets the number of complete 4-byte supported-version entries.
    /// </summary>
    public int SupportedVersionCount => supportedVersionBytes.Length / 4;

    /// <summary>
    /// Gets a supported version by zero-based index.
    /// </summary>
    public uint GetSupportedVersion(int index)
    {
        if ((uint)index >= (uint)SupportedVersionCount)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        return BinaryPrimitives.ReadUInt32BigEndian(supportedVersionBytes.Slice(index * 4, 4));
    }
}
