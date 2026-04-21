namespace Incursa.Quic;

/// <summary>
/// Parses version-independent QUIC packet headers from byte spans.
/// </summary>
internal static class QuicPacketParser
{
    private const int LongHeaderFixedPrefixLength = 1 + sizeof(uint);

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
        if (!IsRecognizableShortHeaderPacket(packet)
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
            if (!IsRecognizableShortHeaderPacket(packet))
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

    /// <summary>
    /// Computes the length of the leading QUIC packet inside a UDP datagram so coalesced packets can be split.
    /// </summary>
    internal static bool TryGetPacketLength(ReadOnlySpan<byte> datagram, out int packetLength)
    {
        packetLength = default;

        if (!TryClassifyHeaderForm(datagram, out QuicHeaderForm headerForm))
        {
            return false;
        }

        if (headerForm == QuicHeaderForm.Short)
        {
            if (!IsRecognizableShortHeaderPacket(datagram))
            {
                return false;
            }

            packetLength = datagram.Length;
            return true;
        }

        if (!QuicPacketParsing.TryParseLongHeaderFields(
                datagram,
                out byte headerControlBits,
                out uint version,
                out ReadOnlySpan<byte> destinationConnectionId,
                out ReadOnlySpan<byte> sourceConnectionId,
                out ReadOnlySpan<byte> versionSpecificData))
        {
            return false;
        }

        int longHeaderPrefixLength = LongHeaderFixedPrefixLength
            + 1
            + destinationConnectionId.Length
            + 1
            + sourceConnectionId.Length;

        if (version != 0 && (headerControlBits & QuicPacketHeaderBits.FixedBitMask) == 0)
        {
            return false;
        }

        if (!QuicPacketParsing.TryValidateVersionSpecificLongHeaderFields(
                headerControlBits,
                version,
                destinationConnectionId.Length,
                sourceConnectionId.Length,
                versionSpecificData))
        {
            return false;
        }

        if (version == QuicVersionNegotiation.VersionNegotiationVersion)
        {
            if (!TryParseVersionNegotiation(datagram, out _))
            {
                return false;
            }

            packetLength = datagram.Length;
            return true;
        }

        if (version != QuicVersionNegotiation.Version1)
        {
            if (!TryParseLongHeader(datagram, out _))
            {
                return false;
            }

            packetLength = datagram.Length;
            return true;
        }

        byte longPacketTypeBits = (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift);
        switch (longPacketTypeBits)
        {
            case QuicLongPacketTypeBits.Initial:
                if (!TryGetInitialVersionSpecificLength(
                        headerControlBits,
                        versionSpecificData,
                        out int initialVersionSpecificLength))
                {
                    return false;
                }

                packetLength = longHeaderPrefixLength + initialVersionSpecificLength;
                return packetLength <= datagram.Length;

            case QuicLongPacketTypeBits.ZeroRtt:
            case QuicLongPacketTypeBits.Handshake:
                if (!TryGetLengthDelimitedVersionSpecificLength(
                        headerControlBits,
                        versionSpecificData,
                        out int lengthDelimitedVersionSpecificLength))
                {
                    return false;
                }

                packetLength = longHeaderPrefixLength + lengthDelimitedVersionSpecificLength;
                return packetLength <= datagram.Length;

            default:
                if (!TryParseLongHeader(datagram, out _))
                {
                    return false;
                }

                packetLength = datagram.Length;
                return true;
        }
    }

    private static bool IsRecognizableShortHeaderPacket(ReadOnlySpan<byte> packet)
    {
        return !packet.IsEmpty
            && (packet[0] & QuicPacketHeaderBits.HeaderFormBitMask) == 0
            && (packet[0] & QuicPacketHeaderBits.FixedBitMask) != 0;
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

    private static bool TryGetInitialVersionSpecificLength(
        byte headerControlBits,
        ReadOnlySpan<byte> versionSpecificData,
        out int versionSpecificLength)
    {
        versionSpecificLength = default;

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes))
        {
            return false;
        }

        int remainingAfterTokenLength = versionSpecificData.Length - tokenLengthBytes;
        if (tokenLength > (ulong)remainingAfterTokenLength
            || tokenLength > (ulong)(int.MaxValue - tokenLengthBytes))
        {
            return false;
        }

        int tokenSectionLength = tokenLengthBytes + checked((int)tokenLength);
        if (!TryGetLengthDelimitedVersionSpecificLength(
                headerControlBits,
                versionSpecificData[tokenSectionLength..],
                out int remainingVersionSpecificLength))
        {
            return false;
        }

        versionSpecificLength = tokenSectionLength + remainingVersionSpecificLength;
        return versionSpecificLength <= versionSpecificData.Length;
    }

    private static bool TryGetLengthDelimitedVersionSpecificLength(
        byte headerControlBits,
        ReadOnlySpan<byte> versionSpecificData,
        out int versionSpecificLength)
    {
        versionSpecificLength = default;

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong lengthFieldValue, out int lengthFieldBytes))
        {
            return false;
        }

        int packetNumberLength = (headerControlBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        if (lengthFieldValue < (ulong)packetNumberLength
            || lengthFieldValue > (ulong)(int.MaxValue - lengthFieldBytes))
        {
            return false;
        }

        int remainingAfterLength = versionSpecificData.Length - lengthFieldBytes;
        if (lengthFieldValue > (ulong)remainingAfterLength)
        {
            return false;
        }

        versionSpecificLength = lengthFieldBytes + checked((int)lengthFieldValue);
        return true;
    }
}
