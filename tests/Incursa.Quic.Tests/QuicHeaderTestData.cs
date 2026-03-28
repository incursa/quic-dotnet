using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

internal static class QuicHeaderTestData
{
    public static byte[] BuildShortHeader(byte headerControlBits, ReadOnlySpan<byte> remainder)
    {
        byte[] packet = new byte[1 + remainder.Length];
        packet[0] = (byte)(headerControlBits & 0x7F);
        remainder.CopyTo(packet.AsSpan(1));
        return packet;
    }

    public static byte[] BuildLongHeader(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> versionSpecificData)
    {
        byte[] packet = new byte[1 + 4 + 1 + destinationConnectionId.Length + 1 + sourceConnectionId.Length + versionSpecificData.Length];
        packet[0] = (byte)(0x80 | (headerControlBits & 0x7F));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, 4), version);
        packet[5] = (byte)destinationConnectionId.Length;

        int sourceConnectionIdLengthOffset = 6 + destinationConnectionId.Length;
        destinationConnectionId.CopyTo(packet.AsSpan(6));
        packet[sourceConnectionIdLengthOffset] = (byte)sourceConnectionId.Length;

        int versionSpecificDataOffset = sourceConnectionIdLengthOffset + 1 + sourceConnectionId.Length;
        sourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1));
        versionSpecificData.CopyTo(packet.AsSpan(versionSpecificDataOffset));

        return packet;
    }

    public static byte[] BuildVersionNegotiation(
        byte headerControlBits,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        params uint[] supportedVersions)
    {
        byte[] supportedVersionBytes = new byte[supportedVersions.Length * sizeof(uint)];
        for (int i = 0; i < supportedVersions.Length; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                supportedVersionBytes.AsSpan(i * sizeof(uint), sizeof(uint)),
                supportedVersions[i]);
        }

        return BuildLongHeader(headerControlBits, 0, destinationConnectionId, sourceConnectionId, supportedVersionBytes);
    }

    public static byte[] BuildTruncatedLongHeader(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> versionSpecificData,
        int truncateBy)
    {
        byte[] packet = BuildLongHeader(
            headerControlBits,
            version,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        return packet[..Math.Max(0, packet.Length - truncateBy)];
    }

    public static byte[] RandomBytes(Random random, int length)
    {
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }
}
