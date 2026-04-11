namespace Incursa.Quic;

/// <summary>
/// Parses version-independent QUIC packet headers from byte spans.
/// </summary>
internal static class QuicPacketParser
{
    /// <summary>
    /// Classifies a packet by the high bit of the first byte.
    /// </summary>
    internal static bool TryClassifyHeaderForm(ReadOnlySpan<byte> packet, out QuicHeaderForm headerForm)
    {
        if (packet.IsEmpty)
        {
            headerForm = default;
            return false;
        }

        headerForm = (packet[0] & QuicPacketHeaderBits.HeaderFormBitMask) == 0 ? QuicHeaderForm.Short : QuicHeaderForm.Long;
        return true;
    }

    /// <summary>
    /// Parses a long-header-form packet into a span-backed view.
    /// </summary>
    internal static bool TryParseLongHeader(ReadOnlySpan<byte> packet, out QuicLongHeaderPacket header)
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

        if (version != 0 && (headerControlBits & QuicPacketHeaderBits.FixedBitMask) == 0)
        {
            header = default;
            return false;
        }

        if (!QuicPacketParsing.TryValidateVersionSpecificLongHeaderFields(
            headerControlBits,
            version,
            destinationConnectionId.Length,
            sourceConnectionId.Length,
            versionSpecificData))
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
    internal static bool TryParseShortHeader(ReadOnlySpan<byte> packet, out QuicShortHeaderPacket header)
    {
        if (packet.IsEmpty
            || (packet[0] & QuicPacketHeaderBits.HeaderFormBitMask) != 0
            || (packet[0] & QuicPacketHeaderBits.FixedBitMask) == 0
            || (packet[0] & QuicPacketHeaderBits.ShortReservedBitsMask) != 0)
        {
            header = default;
            return false;
        }

        header = new QuicShortHeaderPacket((byte)(packet[0] & QuicPacketHeaderBits.HeaderControlBitsMask), packet.Slice(1));
        return true;
    }

    /// <summary>
    /// Parses a Version Negotiation packet.
    /// </summary>
    internal static bool TryParseVersionNegotiation(ReadOnlySpan<byte> packet, out QuicVersionNegotiationPacket header)
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

        if (version != QuicVersionNegotiationPacket.VersionNegotiationVersion
            || supportedVersionBytes.IsEmpty
            || (supportedVersionBytes.Length % QuicVersionNegotiationPacket.SupportedVersionLength) != 0)
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

    /// <summary>
    /// Maps a packet header to its packet number space when the packet uses a supported QUIC packet type.
    /// </summary>
    internal static bool TryGetPacketNumberSpace(ReadOnlySpan<byte> packet, out QuicPacketNumberSpace packetNumberSpace)
    {
        packetNumberSpace = default;

        if (!TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm))
        {
            return false;
        }

        if (headerForm == QuicHeaderForm.Short)
        {
            if (!TryParseShortHeader(packet, out _))
            {
                return false;
            }

            packetNumberSpace = QuicPacketNumberSpace.ApplicationData;
            return true;
        }

        if (!TryParseLongHeader(packet, out QuicLongHeaderPacket header)
            || header.IsVersionNegotiation
            || header.Version != 1)
        {
            return false;
        }

        return TryMapLongHeaderToPacketNumberSpace(header.LongPacketTypeBits, out packetNumberSpace);
    }

    private static bool TryMapLongHeaderToPacketNumberSpace(byte longPacketTypeBits, out QuicPacketNumberSpace packetNumberSpace)
    {
        switch (longPacketTypeBits)
        {
            case QuicLongPacketTypeBits.Initial:
                packetNumberSpace = QuicPacketNumberSpace.Initial;
                return true;
            case QuicLongPacketTypeBits.ZeroRtt:
                packetNumberSpace = QuicPacketNumberSpace.ApplicationData;
                return true;
            case QuicLongPacketTypeBits.Handshake:
                packetNumberSpace = QuicPacketNumberSpace.Handshake;
                return true;
            default:
                packetNumberSpace = default;
                return false;
        }
    }
}

