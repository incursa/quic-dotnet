using System.Buffers.Binary;

namespace Incursa.Quic;

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
