using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

internal static class QuicInitialPacketProtectionTestData
{
    public static byte[] BuildInitialPlaintextPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] versionSpecificData = BuildInitialVersionSpecificData(token, packetNumber, plaintextPayload);
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask | ((packetNumber.Length - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask)),
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);
    }

    private static byte[] BuildInitialVersionSpecificData(
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] tokenLengthBytes = EncodeVarint((ulong)token.Length);
        byte[] lengthBytes = EncodeVarint((ulong)(packetNumber.Length + plaintextPayload.Length + QuicInitialPacketProtection.AuthenticationTagLength));
        byte[] versionSpecificData = new byte[
            tokenLengthBytes.Length
            + token.Length
            + lengthBytes.Length
            + packetNumber.Length
            + plaintextPayload.Length];

        int offset = 0;
        tokenLengthBytes.CopyTo(versionSpecificData, offset);
        offset += tokenLengthBytes.Length;
        token.CopyTo(versionSpecificData.AsSpan(offset));
        offset += token.Length;
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
