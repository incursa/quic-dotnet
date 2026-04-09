namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0008")]
public sealed class REQ_QUIC_RFC9001_S5_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProtectInitialPacket_AndTryOpenInitialPacket_RoundTrip()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            out QuicInitialPacketProtection senderProtection));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            out QuicInitialPacketProtection receiverProtection));

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
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);
        Assert.False(plaintextPacket.AsSpan().SequenceEqual(protectedPacket));

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(
            protectedPacket.AsSpan(0, protectedBytesWritten),
            recoveredPacket,
            out int recoveredBytesWritten));

        Assert.Equal(plaintextPacket.Length, recoveredBytesWritten);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProtectInitialPacket_RejectsPacketsThatCannotProvideAHeaderProtectionSample()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            out QuicInitialPacketProtection protection));

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            sourceConnectionId: [0x01, 0x02, 0x03, 0x04],
            token: [],
            packetNumber: [0x01],
            plaintextPayload: [
                0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18, 0x19,
                0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.False(protection.TryProtect(plaintextPacket, protectedPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialPacketProtection_RoundTripsRandomValidInputs()
    {
        Random random = new(0x5150_2091);

        for (int iteration = 0; iteration < 32; iteration++)
        {
            QuicTlsRole senderRole = random.Next(2) == 0 ? QuicTlsRole.Client : QuicTlsRole.Server;
            QuicTlsRole receiverRole = senderRole == QuicTlsRole.Client ? QuicTlsRole.Server : QuicTlsRole.Client;
            byte[] dcid = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] scid = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] token = QuicHeaderTestData.RandomBytes(random, random.Next(0, 9));
            byte[] packetNumber = QuicHeaderTestData.RandomBytes(random, random.Next(1, 5));
            byte[] plaintextPayload = QuicHeaderTestData.RandomBytes(random, random.Next(20, 65));

            Assert.True(QuicInitialPacketProtection.TryCreate(senderRole, dcid, out QuicInitialPacketProtection senderProtection));
            Assert.True(QuicInitialPacketProtection.TryCreate(receiverRole, dcid, out QuicInitialPacketProtection receiverProtection));

            byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
                dcid,
                scid,
                token,
                packetNumber,
                plaintextPayload);

            byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
            Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
            Assert.Equal(plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength, protectedBytesWritten);

            byte[] recoveredPacket = new byte[plaintextPacket.Length];
            Assert.True(receiverProtection.TryOpen(
                protectedPacket.AsSpan(0, protectedBytesWritten),
                recoveredPacket,
                out int recoveredBytesWritten));

            Assert.Equal(plaintextPacket.Length, recoveredBytesWritten);
            Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));
        }
    }
}
