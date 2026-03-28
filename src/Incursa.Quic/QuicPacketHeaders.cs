using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// Identifies the version-independent QUIC packet header form.
/// </summary>
public enum QuicHeaderForm
{
    /// <summary>
    /// A packet with the first byte high bit cleared.
    /// </summary>
    Short = 0,

    /// <summary>
    /// A packet with the first byte high bit set.
    /// </summary>
    Long = 1,
}

/// <summary>
/// Parses version-independent QUIC packet headers from byte spans.
/// </summary>
public static class QuicPacketParser
{
    /// <summary>
    /// Classifies a packet by the high bit of the first byte.
    /// </summary>
    public static bool TryClassifyHeaderForm(ReadOnlySpan<byte> packet, out QuicHeaderForm headerForm)
    {
        if (packet.IsEmpty)
        {
            headerForm = default;
            return false;
        }

        headerForm = (packet[0] & 0x80) == 0 ? QuicHeaderForm.Short : QuicHeaderForm.Long;
        return true;
    }

    /// <summary>
    /// Parses a long-header-form packet into a span-backed view.
    /// </summary>
    public static bool TryParseLongHeader(ReadOnlySpan<byte> packet, out QuicLongHeaderPacket header)
    {
        if (!QuicPacketParsing.TryParseLongHeaderFields(
            packet,
            out byte headerControlBits,
            out uint version,
            out ReadOnlySpan<byte> destinationConnectionId,
            out ReadOnlySpan<byte> sourceConnectionId,
            out ReadOnlySpan<byte> versionSpecificData))
        {
            header = default;
            return false;
        }

        header = new QuicLongHeaderPacket(
            headerControlBits,
            version,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);
        return true;
    }

    /// <summary>
    /// Parses a short-header-form packet into an opaque remainder view.
    /// </summary>
    public static bool TryParseShortHeader(ReadOnlySpan<byte> packet, out QuicShortHeaderPacket header)
    {
        if (packet.IsEmpty || (packet[0] & 0x80) != 0)
        {
            header = default;
            return false;
        }

        header = new QuicShortHeaderPacket((byte)(packet[0] & 0x7F), packet.Slice(1));
        return true;
    }

    /// <summary>
    /// Parses a Version Negotiation packet.
    /// </summary>
    public static bool TryParseVersionNegotiation(ReadOnlySpan<byte> packet, out QuicVersionNegotiationPacket header)
    {
        if (!QuicPacketParsing.TryParseLongHeaderFields(
            packet,
            out byte headerControlBits,
            out uint version,
            out ReadOnlySpan<byte> destinationConnectionId,
            out ReadOnlySpan<byte> sourceConnectionId,
            out ReadOnlySpan<byte> supportedVersionBytes))
        {
            header = default;
            return false;
        }

        if (version != 0 || supportedVersionBytes.IsEmpty || (supportedVersionBytes.Length & 3) != 0)
        {
            header = default;
            return false;
        }

        header = new QuicVersionNegotiationPacket(
            headerControlBits,
            destinationConnectionId,
            sourceConnectionId,
            supportedVersionBytes);
        return true;
    }
}

/// <summary>
/// A parsed long-header-form packet view.
/// </summary>
public readonly ref struct QuicLongHeaderPacket
{
    private readonly byte _headerControlBits;
    private readonly uint _version;
    private readonly ReadOnlySpan<byte> _destinationConnectionId;
    private readonly ReadOnlySpan<byte> _sourceConnectionId;
    private readonly ReadOnlySpan<byte> _versionSpecificData;

    internal QuicLongHeaderPacket(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> versionSpecificData)
    {
        _headerControlBits = headerControlBits;
        _version = version;
        _destinationConnectionId = destinationConnectionId;
        _sourceConnectionId = sourceConnectionId;
        _versionSpecificData = versionSpecificData;
    }

    /// <summary>
    /// Gets the version-independent header form.
    /// </summary>
    public QuicHeaderForm HeaderForm => QuicHeaderForm.Long;

    /// <summary>
    /// Gets the seven non-form bits from the first byte.
    /// </summary>
    public byte HeaderControlBits => _headerControlBits;

    /// <summary>
    /// Gets the encoded QUIC version.
    /// </summary>
    public uint Version => _version;

    /// <summary>
    /// Gets whether the version field is reserved for version negotiation.
    /// </summary>
    public bool IsVersionNegotiation => _version == 0;

    /// <summary>
    /// Gets the encoded destination connection ID.
    /// </summary>
    public ReadOnlySpan<byte> DestinationConnectionId => _destinationConnectionId;

    /// <summary>
    /// Gets the encoded destination connection ID length in bytes.
    /// </summary>
    public int DestinationConnectionIdLength => _destinationConnectionId.Length;

    /// <summary>
    /// Gets the encoded source connection ID.
    /// </summary>
    public ReadOnlySpan<byte> SourceConnectionId => _sourceConnectionId;

    /// <summary>
    /// Gets the encoded source connection ID length in bytes.
    /// </summary>
    public int SourceConnectionIdLength => _sourceConnectionId.Length;

    /// <summary>
    /// Gets the trailing version-specific bytes.
    /// </summary>
    public ReadOnlySpan<byte> VersionSpecificData => _versionSpecificData;
}

/// <summary>
/// A parsed short-header-form packet view with an opaque remainder.
/// </summary>
public readonly ref struct QuicShortHeaderPacket
{
    private readonly byte _headerControlBits;
    private readonly ReadOnlySpan<byte> _remainder;

    internal QuicShortHeaderPacket(byte headerControlBits, ReadOnlySpan<byte> remainder)
    {
        _headerControlBits = headerControlBits;
        _remainder = remainder;
    }

    /// <summary>
    /// Gets the version-independent header form.
    /// </summary>
    public QuicHeaderForm HeaderForm => QuicHeaderForm.Short;

    /// <summary>
    /// Gets the seven non-form bits from the first byte.
    /// </summary>
    public byte HeaderControlBits => _headerControlBits;

    /// <summary>
    /// Gets the bytes after the first byte as an opaque remainder.
    /// </summary>
    public ReadOnlySpan<byte> Remainder => _remainder;
}

/// <summary>
/// A parsed Version Negotiation packet view.
/// </summary>
public readonly ref struct QuicVersionNegotiationPacket
{
    private readonly byte _headerControlBits;
    private readonly ReadOnlySpan<byte> _destinationConnectionId;
    private readonly ReadOnlySpan<byte> _sourceConnectionId;
    private readonly ReadOnlySpan<byte> _supportedVersionBytes;

    internal QuicVersionNegotiationPacket(
        byte headerControlBits,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> supportedVersionBytes)
    {
        _headerControlBits = headerControlBits;
        _destinationConnectionId = destinationConnectionId;
        _sourceConnectionId = sourceConnectionId;
        _supportedVersionBytes = supportedVersionBytes;
    }

    /// <summary>
    /// Gets the version-independent header form.
    /// </summary>
    public QuicHeaderForm HeaderForm => QuicHeaderForm.Long;

    /// <summary>
    /// Gets the seven non-form bits from the first byte.
    /// </summary>
    public byte HeaderControlBits => _headerControlBits;

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
    public ReadOnlySpan<byte> DestinationConnectionId => _destinationConnectionId;

    /// <summary>
    /// Gets the encoded destination connection ID length in bytes.
    /// </summary>
    public int DestinationConnectionIdLength => _destinationConnectionId.Length;

    /// <summary>
    /// Gets the encoded source connection ID.
    /// </summary>
    public ReadOnlySpan<byte> SourceConnectionId => _sourceConnectionId;

    /// <summary>
    /// Gets the encoded source connection ID length in bytes.
    /// </summary>
    public int SourceConnectionIdLength => _sourceConnectionId.Length;

    /// <summary>
    /// Gets the supported-version bytes as encoded on the wire.
    /// </summary>
    public ReadOnlySpan<byte> SupportedVersionBytes => _supportedVersionBytes;

    /// <summary>
    /// Gets the number of complete 4-byte supported-version entries.
    /// </summary>
    public int SupportedVersionCount => _supportedVersionBytes.Length / 4;

    /// <summary>
    /// Gets a supported version by zero-based index.
    /// </summary>
    public uint GetSupportedVersion(int index)
    {
        if ((uint)index >= (uint)SupportedVersionCount)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        return BinaryPrimitives.ReadUInt32BigEndian(_supportedVersionBytes.Slice(index * 4, 4));
    }
}

internal static class QuicPacketParsing
{
    private const int LongHeaderMinimumLength = 7;

    internal static bool TryParseLongHeaderFields(
        ReadOnlySpan<byte> packet,
        out byte headerControlBits,
        out uint version,
        out ReadOnlySpan<byte> destinationConnectionId,
        out ReadOnlySpan<byte> sourceConnectionId,
        out ReadOnlySpan<byte> trailingData)
    {
        headerControlBits = default;
        version = default;
        destinationConnectionId = default;
        sourceConnectionId = default;
        trailingData = default;

        if (packet.Length < LongHeaderMinimumLength || (packet[0] & 0x80) == 0)
        {
            return false;
        }

        headerControlBits = (byte)(packet[0] & 0x7F);
        version = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(1, sizeof(uint)));

        int destinationConnectionIdLength = packet[5];
        int sourceConnectionIdLengthOffset = 6 + destinationConnectionIdLength;
        if (packet.Length < sourceConnectionIdLengthOffset + 1)
        {
            return false;
        }

        int sourceConnectionIdLength = packet[sourceConnectionIdLengthOffset];
        int sourceConnectionIdOffset = sourceConnectionIdLengthOffset + 1;
        if (packet.Length < sourceConnectionIdOffset + sourceConnectionIdLength)
        {
            return false;
        }

        destinationConnectionId = packet.Slice(6, destinationConnectionIdLength);
        sourceConnectionId = packet.Slice(sourceConnectionIdOffset, sourceConnectionIdLength);
        trailingData = packet.Slice(sourceConnectionIdOffset + sourceConnectionIdLength);
        return true;
    }
}
