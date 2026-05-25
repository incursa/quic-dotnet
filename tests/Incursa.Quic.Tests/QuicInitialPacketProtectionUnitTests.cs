using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

public sealed class QuicInitialPacketProtectionUnitTests
{
    private static readonly byte[] ClientInitialDcid =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    [Fact]
    public void TryDeriveInitialKeyMaterial_UsesDistinctMaterialForVersion1AndVersion2()
    {
        Assert.True(QuicInitialPacketProtection.TryDeriveInitialKeyMaterial(
            QuicVersionNegotiation.Version1,
            ClientInitialDcid,
            out QuicInitialPacketProtectionMaterial v1ClientMaterial,
            out QuicInitialPacketProtectionMaterial v1ServerMaterial));

        Assert.True(QuicInitialPacketProtection.TryDeriveInitialKeyMaterial(
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtectionMaterial v2ClientMaterial,
            out QuicInitialPacketProtectionMaterial v2ServerMaterial));

        Assert.False(v1ClientMaterial.AeadKey.SequenceEqual(v2ClientMaterial.AeadKey));
        Assert.False(v1ServerMaterial.AeadKey.SequenceEqual(v2ServerMaterial.AeadKey));
        Assert.False(v1ClientMaterial.HeaderProtectionKey.SequenceEqual(v2ClientMaterial.HeaderProtectionKey));
    }

    [Fact]
    public void TryCreate_Version2InitialPacketProtector_ProtectsAndOpensVersion2InitialPackets()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtection senderProtection));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtection receiverProtection));

        byte[] plaintextPacket = BuildInitialPlaintextPacket(
            QuicVersionNegotiation.Version2,
            destinationConnectionId: ClientInitialDcid,
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [0xAA, 0xBB],
            packetNumber: [0x01],
            plaintextPayload:
            [
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
        Assert.Equal(protectedPacket.Length, bytesWritten);

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(protectedPacket, recoveredPacket, out int openedBytes));
        Assert.Equal(plaintextPacket.Length, openedBytes);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));
    }

    [Fact]
    public void TryCreate_Version1InitialPacketProtector_DoesNotOpenVersion2InitialPackets()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicVersionNegotiation.Version2,
            ClientInitialDcid,
            out QuicInitialPacketProtection v2SenderProtection));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicVersionNegotiation.Version1,
            ClientInitialDcid,
            out QuicInitialPacketProtection v1ReceiverProtection));

        byte[] plaintextPacket = BuildInitialPlaintextPacket(
            QuicVersionNegotiation.Version2,
            destinationConnectionId: ClientInitialDcid,
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [0xAA, 0xBB],
            packetNumber: [0x01],
            plaintextPayload:
            [
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(v2SenderProtection.TryProtect(plaintextPacket, protectedPacket, out _));

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.False(v1ReceiverProtection.TryOpen(protectedPacket, recoveredPacket, out _));
    }

    private static byte[] BuildInitialPlaintextPacket(
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] versionSpecificData = BuildInitialVersionSpecificData(token, packetNumber, plaintextPayload);
        byte longPacketTypeBits = QuicVersionNegotiation.GetLongHeaderPacketTypeBits(version, QuicLongPacketType.Initial);
        return BuildLongHeader(
            headerControlBits: (byte)(QuicPacketHeaderBits.FixedBitMask
                | (longPacketTypeBits << QuicPacketHeaderBits.LongPacketTypeBitsShift)
                | ((packetNumber.Length - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask)),
            version,
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

    private static byte[] BuildLongHeader(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> versionSpecificData)
    {
        byte[] packet = new byte[1 + sizeof(uint) + 1 + destinationConnectionId.Length + 1 + sourceConnectionId.Length + versionSpecificData.Length];
        packet[0] = (byte)(0x80 | (headerControlBits & 0x7F));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, sizeof(uint)), version);
        packet[5] = (byte)destinationConnectionId.Length;

        int sourceConnectionIdLengthOffset = 6 + destinationConnectionId.Length;
        destinationConnectionId.CopyTo(packet.AsSpan(6));
        packet[sourceConnectionIdLengthOffset] = (byte)sourceConnectionId.Length;

        int versionSpecificDataOffset = sourceConnectionIdLengthOffset + 1 + sourceConnectionId.Length;
        sourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1));
        versionSpecificData.CopyTo(packet.AsSpan(versionSpecificDataOffset));

        return packet;
    }

    private static byte[] EncodeVarint(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        return buffer[..bytesWritten].ToArray();
    }
}
