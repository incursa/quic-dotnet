namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0009")]
public sealed class REQ_QUIC_RFC9001_S5_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProtectInitialPacket_LeavesTheLongHeaderConnectionIdsVisible()
    {
        byte[] clientInitialDcid = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08];
        byte[] sourceConnectionId = [0x01, 0x02, 0x03, 0x04];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            clientInitialDcid,
            out QuicInitialPacketProtection protection));

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: clientInitialDcid,
            sourceConnectionId: sourceConnectionId,
            token: [0xAA, 0xBB],
            packetNumber: [0x01],
            plaintextPayload: [
                0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(protection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));

        Assert.True(clientInitialDcid.AsSpan().SequenceEqual(protectedPacket.AsSpan(6, clientInitialDcid.Length)));
        int sourceConnectionIdOffset = 7 + clientInitialDcid.Length;
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(
            protectedPacket.AsSpan(sourceConnectionIdOffset, sourceConnectionId.Length)));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenInitialPacket_WithDifferentClientInitialDcid_DoesNotSucceed()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            out QuicInitialPacketProtection senderProtection));

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [0xAA, 0xBB],
            packetNumber: [0x01],
            plaintextPayload: [
                0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            [0x01, 0x02, 0x03, 0x04, 0x05],
            out QuicInitialPacketProtection receiverProtection));

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.False(receiverProtection.TryOpen(
            protectedPacket.AsSpan(0, protectedBytesWritten),
            recoveredPacket,
            out _));
    }
}
