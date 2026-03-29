using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

internal static class QuicHeaderTestData
{
    public static byte[] BuildShortHeader(byte headerControlBits, ReadOnlySpan<byte> remainder)
    {
        byte[] packet = new byte[1 + remainder.Length];
        packet[0] = (byte)(0x40 | (headerControlBits & 0x3F));
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

    public static byte[] BuildInitialVersionSpecificData(
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> protectedPayload)
    {
        byte[] tokenLengthBytes = EncodeVarint((ulong)token.Length);
        byte[] payloadLengthBytes = EncodeVarint((ulong)(packetNumber.Length + protectedPayload.Length));
        byte[] versionSpecificData = new byte[
            tokenLengthBytes.Length
            + token.Length
            + payloadLengthBytes.Length
            + packetNumber.Length
            + protectedPayload.Length];

        int offset = 0;
        tokenLengthBytes.CopyTo(versionSpecificData, offset);
        offset += tokenLengthBytes.Length;
        token.CopyTo(versionSpecificData.AsSpan(offset));
        offset += token.Length;
        payloadLengthBytes.CopyTo(versionSpecificData, offset);
        offset += payloadLengthBytes.Length;
        packetNumber.CopyTo(versionSpecificData.AsSpan(offset));
        offset += packetNumber.Length;
        protectedPayload.CopyTo(versionSpecificData.AsSpan(offset));

        return versionSpecificData;
    }

    public static byte[] BuildZeroRttVersionSpecificData(
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> protectedPayload)
    {
        byte[] payloadLengthBytes = EncodeVarint((ulong)(packetNumber.Length + protectedPayload.Length));
        byte[] versionSpecificData = new byte[payloadLengthBytes.Length + packetNumber.Length + protectedPayload.Length];

        int offset = 0;
        payloadLengthBytes.CopyTo(versionSpecificData, offset);
        offset += payloadLengthBytes.Length;
        packetNumber.CopyTo(versionSpecificData.AsSpan(offset));
        offset += packetNumber.Length;
        protectedPayload.CopyTo(versionSpecificData.AsSpan(offset));

        return versionSpecificData;
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

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }
}
