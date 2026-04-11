using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// A parsed Version Negotiation packet view.
/// </summary>
internal readonly ref struct QuicVersionNegotiationPacket
{
    /// <summary>
    /// The version field value carried by Version Negotiation packets.
    /// </summary>
    internal const uint VersionNegotiationVersion = default;

    /// <summary>
    /// Version numbers are 32-bit values, so each supported-version entry is four bytes.
    /// </summary>
    internal const int SupportedVersionLength = sizeof(uint);

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
    internal QuicHeaderForm HeaderForm => QuicHeaderForm.Long;

    /// <summary>
    /// Gets the seven non-form bits from the first byte.
    /// </summary>
    internal byte HeaderControlBits => headerControlBits;

    /// <summary>
    /// Gets the reserved Version value for version negotiation.
    /// </summary>
    internal uint Version => VersionNegotiationVersion;

    /// <summary>
    /// Gets whether this packet is a Version Negotiation packet.
    /// </summary>
    internal bool IsVersionNegotiation => true;

    /// <summary>
    /// Gets the encoded destination connection ID.
    /// </summary>
    internal ReadOnlySpan<byte> DestinationConnectionId => destinationConnectionId;

    /// <summary>
    /// Gets the encoded destination connection ID length in bytes.
    /// </summary>
    internal int DestinationConnectionIdLength => destinationConnectionId.Length;

    /// <summary>
    /// Gets the encoded source connection ID.
    /// </summary>
    internal ReadOnlySpan<byte> SourceConnectionId => sourceConnectionId;

    /// <summary>
    /// Gets the encoded source connection ID length in bytes.
    /// </summary>
    internal int SourceConnectionIdLength => sourceConnectionId.Length;

    /// <summary>
    /// Gets the supported-version bytes as encoded on the wire.
    /// </summary>
    internal ReadOnlySpan<byte> SupportedVersionBytes => supportedVersionBytes;

    /// <summary>
    /// Gets the number of complete 4-byte supported-version entries.
    /// </summary>
    internal int SupportedVersionCount => supportedVersionBytes.Length / SupportedVersionLength;

    /// <summary>
    /// Gets whether the supported-version list contains the specified version.
    /// </summary>
    internal bool ContainsSupportedVersion(uint version)
    {
        for (int offset = 0; offset < supportedVersionBytes.Length; offset += SupportedVersionLength)
        {
            if (BinaryPrimitives.ReadUInt32BigEndian(supportedVersionBytes.Slice(offset, SupportedVersionLength)) == version)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Gets a supported version by zero-based index.
    /// </summary>
    internal uint GetSupportedVersion(int index)
    {
        if ((uint)index >= (uint)SupportedVersionCount)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        return BinaryPrimitives.ReadUInt32BigEndian(supportedVersionBytes.Slice(index * SupportedVersionLength, SupportedVersionLength));
    }
}

