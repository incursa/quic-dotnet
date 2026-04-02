using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// Provides stateless helpers for QUIC version negotiation decisions and packet formatting.
/// </summary>
public static class QuicVersionNegotiation
{
    /// <summary>
    /// The reserved version number that identifies a Version Negotiation packet.
    /// </summary>
    public const uint VersionNegotiationVersion = 0x00000000;

    /// <summary>
    /// The QUIC version number assigned to RFC 9000 version 1.
    /// </summary>
    public const uint Version1 = 0x00000001;

    /// <summary>
    /// The minimum UDP payload size required for QUIC version 1 Initial datagrams.
    /// </summary>
    public const int Version1MinimumDatagramPayloadSize = 1200;

    private const byte VersionNegotiationFirstByte = 0xC0;
    private const uint ReservedVersionMask = 0x0F0F0F0F;
    private const uint ReservedVersionPattern = 0x0A0A0A0A;

    /// <summary>
    /// Computes the largest known minimum datagram size across the supplied supported versions.
    /// </summary>
    public static bool TryGetRequiredInitialDatagramPayloadSize(
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
    public static bool ShouldSendVersionNegotiation(uint clientSelectedVersion, ReadOnlySpan<uint> serverSupportedVersions)
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
    public static bool ShouldSendVersionNegotiation(
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
    /// Determines whether a server should send a Version Negotiation packet for the client's selected version
    /// when the server already sent Version Negotiation packets for this attempt.
    /// </summary>
    public static bool ShouldSendVersionNegotiation(
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
    public static bool TryFormatVersionNegotiationResponse(
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
    public static bool ShouldDiscardVersionNegotiation(
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
    public static bool ShouldAbandonConnectionAttempt(
        QuicVersionNegotiationPacket packet,
        uint selectedVersion,
        ReadOnlySpan<uint> clientSupportedVersions,
        bool hasSuccessfullyProcessedAnotherPacket)
    {
        return SupportsOnlySelectedVersion(clientSupportedVersions, selectedVersion)
            && !ShouldDiscardVersionNegotiation(packet, selectedVersion, hasSuccessfullyProcessedAnotherPacket);
    }

    /// <summary>
    /// Gets whether the supplied version follows the reserved 0x?a?a?a?a pattern.
    /// </summary>
    public static bool IsReservedVersion(uint version)
    {
        return (version & ReservedVersionMask) == ReservedVersionPattern;
    }

    /// <summary>
    /// Creates a reserved version number using the high nibbles from the template value.
    /// </summary>
    public static uint CreateReservedVersion(uint template)
    {
        return (template & 0xF0F0F0F0) | ReservedVersionPattern;
    }

    private static bool SupportsOnlySelectedVersion(ReadOnlySpan<uint> clientSupportedVersions, uint selectedVersion)
    {
        return clientSupportedVersions.Length == 1 && clientSupportedVersions[0] == selectedVersion;
    }

    private static bool TryGetKnownMinimumDatagramPayloadSize(uint version, out int minimumDatagramPayloadSize)
    {
        if (version == Version1)
        {
            minimumDatagramPayloadSize = Version1MinimumDatagramPayloadSize;
            return true;
        }

        minimumDatagramPayloadSize = default;
        return false;
    }
}
