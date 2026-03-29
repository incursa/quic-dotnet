using System.Buffers.Binary;

namespace Incursa.Quic;

internal static class QuicPacketParsing
{
    private const int LongHeaderMinimumLength = 7;
    private const int MaximumRfc9000ConnectionIdLength = 20;
    private const int Version1MaximumConnectionIdLength = 20;

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
        if (version == 1 && destinationConnectionIdLength > Version1MaximumConnectionIdLength)
        {
            return false;
        }

        int sourceConnectionIdLengthOffset = 6 + destinationConnectionIdLength;
        if (packet.Length < sourceConnectionIdLengthOffset + 1)
        {
            return false;
        }

        int sourceConnectionIdLength = packet[sourceConnectionIdLengthOffset];
        if (version == 1 && sourceConnectionIdLength > Version1MaximumConnectionIdLength)
        {
            return false;
        }

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

    internal static bool TryValidateVersionSpecificLongHeaderFields(
        byte headerControlBits,
        uint version,
        int destinationConnectionIdLength,
        int sourceConnectionIdLength,
        ReadOnlySpan<byte> versionSpecificData)
    {
        if (version != 1)
        {
            return true;
        }

        byte longPacketTypeBits = (byte)((headerControlBits & 0x30) >> 4);
        return longPacketTypeBits switch
        {
            0x00 => TryValidateInitialPacketFields(
                headerControlBits,
                destinationConnectionIdLength,
                sourceConnectionIdLength,
                versionSpecificData),
            0x01 => TryValidateZeroRttPacketFields(
                headerControlBits,
                destinationConnectionIdLength,
                sourceConnectionIdLength,
                versionSpecificData),
            _ => true,
        };
    }

    private static bool TryValidateInitialPacketFields(
        byte headerControlBits,
        int destinationConnectionIdLength,
        int sourceConnectionIdLength,
        ReadOnlySpan<byte> versionSpecificData)
    {
        if (destinationConnectionIdLength > MaximumRfc9000ConnectionIdLength
            || sourceConnectionIdLength > MaximumRfc9000ConnectionIdLength)
        {
            return false;
        }

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes))
        {
            return false;
        }

        int remainingAfterTokenLength = versionSpecificData.Length - tokenLengthBytes;
        if (tokenLength > (ulong)remainingAfterTokenLength)
        {
            return false;
        }

        ReadOnlySpan<byte> remainder = versionSpecificData.Slice(tokenLengthBytes + (int)tokenLength);
        return TryValidateLengthAndPacketNumberFields(headerControlBits, remainder);
    }

    private static bool TryValidateZeroRttPacketFields(
        byte headerControlBits,
        int destinationConnectionIdLength,
        int sourceConnectionIdLength,
        ReadOnlySpan<byte> versionSpecificData)
    {
        if (destinationConnectionIdLength > MaximumRfc9000ConnectionIdLength
            || sourceConnectionIdLength > MaximumRfc9000ConnectionIdLength)
        {
            return false;
        }

        return TryValidateLengthAndPacketNumberFields(headerControlBits, versionSpecificData);
    }

    private static bool TryValidateLengthAndPacketNumberFields(
        byte headerControlBits,
        ReadOnlySpan<byte> encodedLengthAndPacketNumber)
    {
        if (!QuicVariableLengthInteger.TryParse(
            encodedLengthAndPacketNumber,
            out ulong packetPayloadLength,
            out int lengthBytes))
        {
            return false;
        }

        int packetNumberLength = (headerControlBits & 0x03) + 1;
        if (packetPayloadLength < (ulong)packetNumberLength)
        {
            return false;
        }

        int remainingAfterLength = encodedLengthAndPacketNumber.Length - lengthBytes;
        if (packetPayloadLength > (ulong)remainingAfterLength)
        {
            return false;
        }

        return true;
    }
}
