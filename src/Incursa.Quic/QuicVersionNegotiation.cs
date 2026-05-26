using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// Provides stateless helpers for QUIC version negotiation decisions and packet formatting.
/// </summary>
internal static class QuicVersionNegotiation
{
    /// <summary>
    /// The reserved version number that identifies a Version Negotiation packet.
    /// RFC 9000 uses version 0 as the version-negotiation sentinel.
    /// </summary>
    internal const uint VersionNegotiationVersion = 0x00000000;

    /// <summary>
    /// The QUIC version number assigned to RFC 9000 version 1.
    /// </summary>
    internal const uint Version1 = 0x00000001;

    /// <summary>
    /// The QUIC version number assigned to RFC 9369 version 2.
    /// </summary>
    internal const uint Version2 = 0x6B3343CF;

    private const byte Version2InitialLongPacketTypeBits = 0x01;
    private const byte Version2ZeroRttLongPacketTypeBits = 0x02;
    private const byte Version2HandshakeLongPacketTypeBits = 0x03;
    private const byte Version2RetryLongPacketTypeBits = 0x00;

    /// <summary>
    /// The minimum UDP payload size required for QUIC version 1 Initial datagrams.
    /// RFC 9000 requires a 1200-byte Initial payload to avoid fragmentation assumptions.
    /// </summary>
    internal const int Version1MinimumDatagramPayloadSize = 1200;

    /// <summary>
    /// The maximum connection-id length allowed by RFC 9000 version 1 long-header parsing.
    /// </summary>
    private const int Version1MaximumConnectionIdLength = 20;

    /// <summary>
    /// The first byte used when formatting a Version Negotiation packet.
    /// </summary>
    private const byte VersionNegotiationFirstByte = QuicPacketHeaderBits.HeaderFormBitMask | QuicPacketHeaderBits.FixedBitMask;

    /// <summary>
    /// The reserved-version pattern mask used by RFC 9000, 0x0F0F0F0F.
    /// </summary>
    private const uint ReservedVersionMask = 0x0F0F0F0F;

    /// <summary>
    /// The mask that identifies versions with the top 16 bits cleared.
    /// </summary>
    private const uint FutureIetfConsensusReservedVersionMask = 0xFFFF0000;

    /// <summary>
    /// The reserved-version pattern value used by RFC 9000, 0x0A0A0A0A.
    /// </summary>
    private const uint ReservedVersionPattern = 0x0A0A0A0A;

    /// <summary>
    /// The mask that preserves the template's high nibbles when synthesizing reserved versions.
    /// </summary>
    private const uint ReservedVersionTemplateMask = 0xF0F0F0F0;

    /// <summary>
    /// Gets whether the supplied version is the reserved Version Negotiation sentinel.
    /// </summary>
    internal static bool IsVersionNegotiationVersion(uint version)
    {
        return version == VersionNegotiationVersion;
    }

    /// <summary>
    /// Gets whether the supplied version is RFC 9000 version 1.
    /// </summary>
    internal static bool IsVersion1(uint version)
    {
        return version == Version1;
    }

    /// <summary>
    /// Gets whether the supplied version is one of the supported handshake/packet-crypto versions.
    /// </summary>
    internal static bool IsSupportedTransportVersion(uint version)
    {
        return version == Version1 || version == Version2;
    }

    /// <summary>
    /// Gets whether two supported transport versions can be upgraded or downgraded without a round trip.
    /// </summary>
    internal static bool AreCompatibleVersions(uint left, uint right)
    {
        if (left == right)
        {
            return IsSupportedTransportVersion(left);
        }

        return (left == Version1 && right == Version2)
            || (left == Version2 && right == Version1);
    }

    /// <summary>
    /// Selects a compatible version from the client's offered list using the server's supported ordering.
    /// The selector prefers a compatible alternative over the client's original version when one exists.
    /// </summary>
    internal static bool TrySelectCompatibleVersion(
        uint clientOriginalVersion,
        ReadOnlySpan<uint> clientAvailableVersions,
        ReadOnlySpan<uint> serverSupportedVersions,
        out uint selectedVersion)
    {
        selectedVersion = default;

        if (clientAvailableVersions.IsEmpty || serverSupportedVersions.IsEmpty)
        {
            return false;
        }

        for (int index = 0; index < serverSupportedVersions.Length; index++)
        {
            uint candidateVersion = serverSupportedVersions[index];
            if (candidateVersion == clientOriginalVersion
                || !IsSupportedTransportVersion(candidateVersion)
                || !AreCompatibleVersions(clientOriginalVersion, candidateVersion)
                || !ContainsVersion(clientAvailableVersions, candidateVersion))
            {
                continue;
            }

            selectedVersion = candidateVersion;
            return true;
        }

        if (!IsSupportedTransportVersion(clientOriginalVersion)
            || !ContainsVersion(clientAvailableVersions, clientOriginalVersion)
            || !ContainsVersion(serverSupportedVersions, clientOriginalVersion))
        {
            return false;
        }

        selectedVersion = clientOriginalVersion;
        return true;
    }

    /// <summary>
    /// Reorders the supported version list so the selected version appears first.
    /// </summary>
    internal static bool TryMoveVersionToFront(
        ReadOnlySpan<uint> supportedVersions,
        uint selectedVersion,
        out uint[] reorderedVersions)
    {
        reorderedVersions = [];

        if (supportedVersions.IsEmpty)
        {
            return false;
        }

        int selectedIndex = -1;
        for (int index = 0; index < supportedVersions.Length; index++)
        {
            if (supportedVersions[index] == selectedVersion)
            {
                selectedIndex = index;
                break;
            }
        }

        if (selectedIndex < 0)
        {
            return false;
        }

        reorderedVersions = new uint[supportedVersions.Length];
        reorderedVersions[0] = selectedVersion;
        int reorderedIndex = 1;
        for (int index = 0; index < supportedVersions.Length; index++)
        {
            uint candidate = supportedVersions[index];
            if (candidate == selectedVersion)
            {
                continue;
            }

            reorderedVersions[reorderedIndex++] = candidate;
        }

        return true;
    }

    /// <summary>
    /// Gets the maximum connection-id length allowed by the current version policy.
    /// Version 1 keeps the RFC 9000 limit; later versions remain version-neutral here.
    /// </summary>
    internal static int GetLongHeaderConnectionIdLengthLimit(uint version)
    {
        return IsSupportedTransportVersion(version) ? Version1MaximumConnectionIdLength : byte.MaxValue;
    }

    /// <summary>
    /// Gets the minimum datagram payload floor for an Initial packet under the current version policy.
    /// </summary>
    internal static int GetMinimumInitialDatagramPayloadSize(uint version)
    {
        return IsSupportedTransportVersion(version) ? Version1MinimumDatagramPayloadSize : 0;
    }

    /// <summary>
    /// Computes the largest known minimum datagram size across the supplied supported versions.
    /// </summary>
    internal static bool TryGetRequiredInitialDatagramPayloadSize(
        ReadOnlySpan<uint> supportedVersions,
        out int requiredPayloadSize)
    {
        if (supportedVersions.IsEmpty)
        {
            requiredPayloadSize = default;
            return false;
        }

        int largestKnownMinimum = 0;
        for (int index = 0; index < supportedVersions.Length; index++)
        {
            if (!TryGetKnownMinimumDatagramPayloadSize(supportedVersions[index], out int minimumDatagramPayloadSize))
            {
                requiredPayloadSize = default;
                return false;
            }

            largestKnownMinimum = Math.Max(largestKnownMinimum, minimumDatagramPayloadSize);
        }

        requiredPayloadSize = largestKnownMinimum;
        return true;
    }

    /// <summary>
    /// Determines whether a server should send a Version Negotiation packet for the client's selected version.
    /// </summary>
    internal static bool ShouldSendVersionNegotiation(uint clientSelectedVersion, ReadOnlySpan<uint> serverSupportedVersions)
    {
        if (clientSelectedVersion == VersionNegotiationVersion || serverSupportedVersions.IsEmpty)
        {
            return false;
        }

        for (int index = 0; index < serverSupportedVersions.Length; index++)
        {
            if (serverSupportedVersions[index] == clientSelectedVersion)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Determines whether a server should send a Version Negotiation packet for the client's selected version
    /// and the observed datagram payload size.
    /// </summary>
    internal static bool ShouldSendVersionNegotiation(
        uint clientSelectedVersion,
        int datagramPayloadSize,
        ReadOnlySpan<uint> serverSupportedVersions)
    {
        if (!ShouldSendVersionNegotiation(clientSelectedVersion, serverSupportedVersions)
            || !TryGetRequiredInitialDatagramPayloadSize(serverSupportedVersions, out int requiredPayloadSize))
        {
            return false;
        }

        return datagramPayloadSize >= requiredPayloadSize;
    }

    /// <summary>
    /// Determines whether a server should send a Version Negotiation packet when response limiting is active.
    /// </summary>
    internal static bool ShouldSendVersionNegotiation(
        uint clientSelectedVersion,
        int datagramPayloadSize,
        ReadOnlySpan<uint> serverSupportedVersions,
        bool hasAlreadySentVersionNegotiation)
    {
        return !hasAlreadySentVersionNegotiation
            && ShouldSendVersionNegotiation(clientSelectedVersion, datagramPayloadSize, serverSupportedVersions);
    }

    /// <summary>
    /// Determines whether a server should send a Version Negotiation packet for the client's selected version
    /// when the server already sent Version Negotiation packets for this attempt.
    /// </summary>
    internal static bool ShouldSendVersionNegotiation(
        uint clientSelectedVersion,
        ReadOnlySpan<uint> serverSupportedVersions,
        bool hasAlreadySentVersionNegotiation)
    {
        return !hasAlreadySentVersionNegotiation
            && ShouldSendVersionNegotiation(clientSelectedVersion, serverSupportedVersions);
    }

    /// <summary>
    /// Formats a Version Negotiation response that echoes the client's connection IDs and advertises the server's accepted versions.
    /// </summary>
    internal static bool TryFormatVersionNegotiationResponse(
        uint clientSelectedVersion,
        ReadOnlySpan<byte> clientDestinationConnectionId,
        ReadOnlySpan<byte> clientSourceConnectionId,
        ReadOnlySpan<uint> serverSupportedVersions,
        Span<byte> destination,
        out int bytesWritten)
    {
        if (!ShouldSendVersionNegotiation(clientSelectedVersion, serverSupportedVersions)
            || clientDestinationConnectionId.Length > byte.MaxValue
            || clientSourceConnectionId.Length > byte.MaxValue)
        {
            bytesWritten = default;
            return false;
        }

        int supportedVersionBytesLength = serverSupportedVersions.Length * sizeof(uint);
        int packetLength =
            1
            + sizeof(uint)
            + 1
            + clientSourceConnectionId.Length
            + 1
            + clientDestinationConnectionId.Length
            + supportedVersionBytesLength;

        if (destination.Length < packetLength)
        {
            bytesWritten = default;
            return false;
        }

        for (int index = 0; index < serverSupportedVersions.Length; index++)
        {
            if (serverSupportedVersions[index] == VersionNegotiationVersion)
            {
                bytesWritten = default;
                return false;
            }
        }

        int offset = 0;
        destination[offset++] = VersionNegotiationFirstByte;
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset, sizeof(uint)), VersionNegotiationVersion);
        offset += sizeof(uint);

        destination[offset++] = (byte)clientSourceConnectionId.Length;
        clientSourceConnectionId.CopyTo(destination.Slice(offset, clientSourceConnectionId.Length));
        offset += clientSourceConnectionId.Length;

        destination[offset++] = (byte)clientDestinationConnectionId.Length;
        clientDestinationConnectionId.CopyTo(destination.Slice(offset, clientDestinationConnectionId.Length));
        offset += clientDestinationConnectionId.Length;

        for (int index = 0; index < serverSupportedVersions.Length; index++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset, sizeof(uint)), serverSupportedVersions[index]);
            offset += sizeof(uint);
        }

        bytesWritten = offset;
        return true;
    }

    /// <summary>
    /// Determines whether a client must discard a Version Negotiation packet.
    /// </summary>
    internal static bool ShouldDiscardVersionNegotiation(
        QuicVersionNegotiationPacket packet,
        uint selectedVersion,
        bool hasSuccessfullyProcessedAnotherPacket)
    {
        if (hasSuccessfullyProcessedAnotherPacket)
        {
            return true;
        }

        for (int index = 0; index < packet.SupportedVersionCount; index++)
        {
            if (packet.GetSupportedVersion(index) == selectedVersion)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Determines whether a client must abandon the current connection attempt after receiving a Version Negotiation packet.
    /// </summary>
    internal static bool ShouldAbandonConnectionAttempt(
        QuicVersionNegotiationPacket packet,
        uint selectedVersion,
        ReadOnlySpan<uint> clientSupportedVersions,
        bool hasSuccessfullyProcessedAnotherPacket)
    {
        return clientSupportedVersions.Length <= 1
            && !ShouldDiscardVersionNegotiation(packet, selectedVersion, hasSuccessfullyProcessedAnotherPacket);
    }

    /// <summary>
    /// Gets whether the supplied version follows the reserved 0x?a?a?a?a pattern.
    /// </summary>
    internal static bool IsReservedVersion(uint version)
    {
        return (version & ReservedVersionMask) == ReservedVersionPattern;
    }

    /// <summary>
    /// Gets whether the supplied version falls in the future IETF consensus reserved range.
    /// </summary>
    internal static bool IsFutureIetfConsensusReservedVersion(uint version)
    {
        return (version & FutureIetfConsensusReservedVersionMask) == 0;
    }

    /// <summary>
    /// Creates a reserved version number using the high nibbles from the template value.
    /// </summary>
    internal static uint CreateReservedVersion(uint template)
    {
        return (template & ReservedVersionTemplateMask) | ReservedVersionPattern;
    }

    private static bool TryGetKnownMinimumDatagramPayloadSize(uint version, out int minimumDatagramPayloadSize)
    {
        if (IsSupportedTransportVersion(version))
        {
            minimumDatagramPayloadSize = Version1MinimumDatagramPayloadSize;
            return true;
        }

        minimumDatagramPayloadSize = default;
        return false;
    }

    /// <summary>
    /// Gets the logical long-header packet type bits for a specific version.
    /// </summary>
    internal static byte GetLongHeaderPacketTypeBits(uint version, QuicLongPacketType packetType)
    {
        if (version == Version1)
        {
            return packetType switch
            {
                QuicLongPacketType.Initial => QuicLongPacketTypeBits.Initial,
                QuicLongPacketType.ZeroRtt => QuicLongPacketTypeBits.ZeroRtt,
                QuicLongPacketType.Handshake => QuicLongPacketTypeBits.Handshake,
                QuicLongPacketType.Retry => QuicLongPacketTypeBits.Retry,
                _ => throw new ArgumentOutOfRangeException(nameof(packetType)),
            };
        }

        if (version == Version2)
        {
            return packetType switch
            {
                QuicLongPacketType.Initial => Version2InitialLongPacketTypeBits,
                QuicLongPacketType.ZeroRtt => Version2ZeroRttLongPacketTypeBits,
                QuicLongPacketType.Handshake => Version2HandshakeLongPacketTypeBits,
                QuicLongPacketType.Retry => Version2RetryLongPacketTypeBits,
                _ => throw new ArgumentOutOfRangeException(nameof(packetType)),
            };
        }

        return packetType switch
        {
            QuicLongPacketType.Initial => QuicLongPacketTypeBits.Initial,
            QuicLongPacketType.ZeroRtt => QuicLongPacketTypeBits.ZeroRtt,
            QuicLongPacketType.Handshake => QuicLongPacketTypeBits.Handshake,
            QuicLongPacketType.Retry => QuicLongPacketTypeBits.Retry,
            _ => throw new ArgumentOutOfRangeException(nameof(packetType)),
        };
    }

    /// <summary>
    /// Gets whether the encoded long-header packet type bits match the requested logical packet type for the version.
    /// </summary>
    internal static bool IsLongHeaderPacketType(uint version, byte packetTypeBits, QuicLongPacketType packetType)
    {
        return IsSupportedTransportVersion(version)
            && packetTypeBits == GetLongHeaderPacketTypeBits(version, packetType);
    }

    /// <summary>
    /// Maps version-specific long-header packet type bits back to their logical packet type.
    /// </summary>
    internal static bool TryGetLongHeaderPacketType(uint version, byte packetTypeBits, out QuicLongPacketType packetType)
    {
        if (version == Version1)
        {
            switch (packetTypeBits)
            {
                case QuicLongPacketTypeBits.Initial:
                    packetType = QuicLongPacketType.Initial;
                    return true;
                case QuicLongPacketTypeBits.ZeroRtt:
                    packetType = QuicLongPacketType.ZeroRtt;
                    return true;
                case QuicLongPacketTypeBits.Handshake:
                    packetType = QuicLongPacketType.Handshake;
                    return true;
                case QuicLongPacketTypeBits.Retry:
                    packetType = QuicLongPacketType.Retry;
                    return true;
                default:
                    packetType = default;
                    return false;
            }
        }

        if (version == Version2)
        {
            switch (packetTypeBits)
            {
                case Version2InitialLongPacketTypeBits:
                    packetType = QuicLongPacketType.Initial;
                    return true;
                case Version2ZeroRttLongPacketTypeBits:
                    packetType = QuicLongPacketType.ZeroRtt;
                    return true;
                case Version2HandshakeLongPacketTypeBits:
                    packetType = QuicLongPacketType.Handshake;
                    return true;
                case Version2RetryLongPacketTypeBits:
                    packetType = QuicLongPacketType.Retry;
                    return true;
                default:
                    packetType = default;
                    return false;
            }
        }

        packetType = default;
        return false;
    }

    private static bool ContainsVersion(ReadOnlySpan<uint> versions, uint candidateVersion)
    {
        for (int index = 0; index < versions.Length; index++)
        {
            if (versions[index] == candidateVersion)
            {
                return true;
            }
        }

        return false;
    }
}
