using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Provides Retry packet integrity generation and validation using the RFC 9001 fixed AEAD inputs.
/// </summary>
internal static class QuicRetryIntegrity
{
    private const int LongHeaderFormLength = 1;
    private const int LongHeaderVersionLength = sizeof(uint);
    private const int DestinationConnectionIdLengthOffset = LongHeaderFormLength + LongHeaderVersionLength;
    private const int DestinationConnectionIdOffset = DestinationConnectionIdLengthOffset + 1;

    /// <summary>
    /// Retry integrity tags are 16 bytes long.
    /// </summary>
    internal const int RetryIntegrityTagLength = 16;

    private static readonly byte[] RetryIntegrityKeyBytes =
    [
        0xBE, 0x0C, 0x69, 0x0B, 0x9F, 0x66, 0x57, 0x5A,
        0x1D, 0x76, 0x6B, 0x54, 0xE3, 0x68, 0xC8, 0x4E,
    ];

    private static readonly byte[] RetryIntegrityNonceBytes =
    [
        0x46, 0x15, 0x99, 0xD3, 0x5D, 0x63, 0x2B, 0xF2,
        0x23, 0x98, 0x25, 0xBB,
    ];

    /// <summary>
    /// Gets the fixed Retry integrity key from RFC 9001 Section 5.8.
    /// </summary>
    internal static ReadOnlySpan<byte> RetryIntegrityKey => RetryIntegrityKeyBytes;

    /// <summary>
    /// Gets the fixed Retry integrity nonce from RFC 9001 Section 5.8.
    /// </summary>
    internal static ReadOnlySpan<byte> RetryIntegrityNonce => RetryIntegrityNonceBytes;

    /// <summary>
    /// Builds a full Retry packet with a valid integrity tag from the supplied connection IDs and token.
    /// </summary>
    internal static bool TryBuildRetryPacket(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retryPacketDestinationConnectionId,
        ReadOnlySpan<byte> retrySourceConnectionId,
        ReadOnlySpan<byte> retryToken,
        out byte[] retryPacket)
    {
        retryPacket = [];

        if (retryPacketDestinationConnectionId.Length > byte.MaxValue
            || retrySourceConnectionId.Length > byte.MaxValue)
        {
            return false;
        }

        if (originalDestinationConnectionId.SequenceEqual(retrySourceConnectionId))
        {
            // Retry packets must not reuse the client's Initial DCID as their Source CID.
            return false;
        }

        long packetLengthLong =
            1L
            + sizeof(uint)
            + 1L
            + retryPacketDestinationConnectionId.Length
            + 1L
            + retrySourceConnectionId.Length
            + retryToken.Length
            + RetryIntegrityTagLength;
        if (packetLengthLong > int.MaxValue)
        {
            return false;
        }

        int packetLength = (int)packetLengthLong;
        byte[] packet = new byte[packetLength];
        packet[0] = (byte)(
            QuicPacketHeaderBits.HeaderFormBitMask
            | QuicPacketHeaderBits.FixedBitMask
            | (QuicLongPacketTypeBits.Retry << QuicPacketHeaderBits.LongPacketTypeBitsShift));

        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(LongHeaderFormLength, sizeof(uint)), QuicVersionNegotiation.Version1);

        packet[DestinationConnectionIdLengthOffset] = (byte)retryPacketDestinationConnectionId.Length;
        retryPacketDestinationConnectionId.CopyTo(packet.AsSpan(DestinationConnectionIdOffset));

        int sourceConnectionIdLengthOffset = DestinationConnectionIdOffset + retryPacketDestinationConnectionId.Length;
        packet[sourceConnectionIdLengthOffset] = (byte)retrySourceConnectionId.Length;
        retrySourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1));

        int versionSpecificDataOffset = sourceConnectionIdLengthOffset + 1 + retrySourceConnectionId.Length;
        retryToken.CopyTo(packet.AsSpan(versionSpecificDataOffset));

        if (!TryGenerateRetryIntegrityTag(
            originalDestinationConnectionId,
            packet.AsSpan(0, packet.Length - RetryIntegrityTagLength),
            packet.AsSpan(packet.Length - RetryIntegrityTagLength),
            out int integrityTagBytesWritten)
            || integrityTagBytesWritten != RetryIntegrityTagLength)
        {
            return false;
        }

        retryPacket = packet;
        return true;
    }

    /// <summary>
    /// Generates the Retry integrity tag for a Retry packet without its trailing tag field.
    /// </summary>
    internal static bool TryGenerateRetryIntegrityTag(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retryPacketWithoutIntegrityTag,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (destination.Length < RetryIntegrityTagLength)
        {
            return false;
        }

        if (!TryBuildRetryAssociatedData(
            originalDestinationConnectionId,
            retryPacketWithoutIntegrityTag,
            out byte[]? associatedDataBuffer,
            out int associatedDataLength))
        {
            return false;
        }

        try
        {
            using AesGcm aead = new(RetryIntegrityKeyBytes, RetryIntegrityTagLength);
            aead.Encrypt(
                RetryIntegrityNonceBytes,
                ReadOnlySpan<byte>.Empty,
                Span<byte>.Empty,
                destination[..RetryIntegrityTagLength],
                associatedDataBuffer.AsSpan(0, associatedDataLength));

            bytesWritten = RetryIntegrityTagLength;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            ReleaseAssociatedDataBuffer(associatedDataBuffer, associatedDataLength);
        }
    }

    /// <summary>
    /// Validates the Retry integrity tag for a full Retry packet.
    /// </summary>
    internal static bool TryValidateRetryPacketIntegrity(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retryPacket)
    {
        if (retryPacket.Length < RetryIntegrityTagLength)
        {
            return false;
        }

        ReadOnlySpan<byte> retryPacketWithoutIntegrityTag = retryPacket[..^RetryIntegrityTagLength];
        ReadOnlySpan<byte> retryIntegrityTag = retryPacket[^RetryIntegrityTagLength..];

        if (!TryBuildRetryAssociatedData(
            originalDestinationConnectionId,
            retryPacketWithoutIntegrityTag,
            out byte[]? associatedDataBuffer,
            out int associatedDataLength))
        {
            return false;
        }

        try
        {
            using AesGcm aead = new(RetryIntegrityKeyBytes, RetryIntegrityTagLength);
            aead.Decrypt(
                RetryIntegrityNonceBytes,
                ReadOnlySpan<byte>.Empty,
                retryIntegrityTag,
                Span<byte>.Empty,
                associatedDataBuffer.AsSpan(0, associatedDataLength));

            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            ReleaseAssociatedDataBuffer(associatedDataBuffer, associatedDataLength);
        }
    }

    private static bool TryBuildRetryAssociatedData(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retryPacket,
        out byte[]? associatedDataBuffer,
        out int associatedDataLength)
    {
        associatedDataBuffer = default;
        associatedDataLength = default;

        if (originalDestinationConnectionId.Length > byte.MaxValue)
        {
            return false;
        }

        if (!QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket header)
            || header.Version != 1
            || header.LongPacketTypeBits != QuicLongPacketTypeBits.Retry)
        {
            return false;
        }

        if (retryPacket.Length > int.MaxValue - originalDestinationConnectionId.Length - 1)
        {
            return false;
        }

        associatedDataLength = 1 + originalDestinationConnectionId.Length + retryPacket.Length;
        associatedDataBuffer = ArrayPool<byte>.Shared.Rent(associatedDataLength);

        Span<byte> associatedData = associatedDataBuffer.AsSpan(0, associatedDataLength);
        associatedData[0] = (byte)originalDestinationConnectionId.Length;
        originalDestinationConnectionId.CopyTo(associatedData[1..]);
        retryPacket.CopyTo(associatedData[(1 + originalDestinationConnectionId.Length)..]);
        return true;
    }

    private static void ReleaseAssociatedDataBuffer(byte[]? associatedDataBuffer, int associatedDataLength)
    {
        if (associatedDataBuffer is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(associatedDataBuffer.AsSpan(0, associatedDataLength));
        ArrayPool<byte>.Shared.Return(associatedDataBuffer);
    }

    /// <summary>
    /// Parses the Retry metadata needed for the library-owned one-replay bootstrap handoff.
    /// </summary>
    internal static bool TryParseRetryBootstrapMetadata(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> retryPacket,
        out QuicRetryBootstrapMetadata metadata)
    {
        metadata = default;

        if (!TryValidateRetryPacketIntegrity(originalDestinationConnectionId, retryPacket)
            || !QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket retryHeader)
            || retryHeader.Version != 1
            || retryHeader.LongPacketTypeBits != QuicLongPacketTypeBits.Retry
            || retryHeader.VersionSpecificData.Length <= RetryIntegrityTagLength
            || retryHeader.SourceConnectionId.IsEmpty)
        {
            return false;
        }

        ReadOnlySpan<byte> retryToken = retryHeader.VersionSpecificData[..^RetryIntegrityTagLength];
        if (retryToken.IsEmpty)
        {
            return false;
        }

        metadata = new QuicRetryBootstrapMetadata(
            retryHeader.SourceConnectionId.ToArray(),
            retryToken.ToArray());
        return true;
    }
}

internal readonly record struct QuicRetryBootstrapMetadata(
    byte[] RetrySourceConnectionId,
    byte[] RetryToken);
