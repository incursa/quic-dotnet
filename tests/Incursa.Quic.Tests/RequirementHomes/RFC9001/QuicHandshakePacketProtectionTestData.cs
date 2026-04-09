using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

internal static class QuicHandshakePacketProtectionTestData
{
    public static byte[] BuildHandshakePlaintextPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] versionSpecificData = BuildHandshakeVersionSpecificData(packetNumber, plaintextPayload);
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(0x60 | ((packetNumber.Length - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask)),
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);
    }

    private static byte[] BuildHandshakeVersionSpecificData(
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] lengthBytes = EncodeVarint((ulong)(packetNumber.Length + plaintextPayload.Length + QuicInitialPacketProtection.AuthenticationTagLength));
        byte[] versionSpecificData = new byte[lengthBytes.Length + packetNumber.Length + plaintextPayload.Length];

        int offset = 0;
        lengthBytes.CopyTo(versionSpecificData, offset);
        offset += lengthBytes.Length;
        packetNumber.CopyTo(versionSpecificData.AsSpan(offset));
        offset += packetNumber.Length;
        plaintextPayload.CopyTo(versionSpecificData.AsSpan(offset));

        return versionSpecificData;
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }
}
