namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0007")]
public sealed class REQ_QUIC_RFC9001_S5_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProtectHandshakePacket_AndTryOpenHandshakePacket_RoundTrip()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Ccm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection senderProtection));
        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection receiverProtection));

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId: [0x10, 0x11, 0x12, 0x13],
            sourceConnectionId: [0x20, 0x21],
            packetNumber: [0x01, 0x02],
            plaintextPayload:
            [
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
                0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
                0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
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
    public void TryCreate_RejectsMissingMaterial()
    {
        QuicTlsPacketProtectionMaterial? missingMaterial = null;

        Assert.False(QuicHandshakePacketProtection.TryCreate(missingMaterial, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreate_RejectsWrongLevelMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes256Gcm,
            CreateSequentialBytes(0x11, 32),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 32),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        Assert.False(QuicHandshakePacketProtection.TryCreate(material, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenHandshakePacket_RejectsTamperedProtectedPayload()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes256Gcm,
            CreateSequentialBytes(0x11, 32),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 32),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection senderProtection));
        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection receiverProtection));

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId: [0x10, 0x11, 0x12, 0x13],
            sourceConnectionId: [0x20, 0x21],
            packetNumber: [0x01],
            plaintextPayload:
            [
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
                0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
                0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));

        protectedPacket[^1] ^= 0x80;

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.False(receiverProtection.TryOpen(
            protectedPacket.AsSpan(0, protectedBytesWritten),
            recoveredPacket,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProtectHandshakePacket_RejectsPacketsThatCannotProvideAHeaderProtectionSample()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Ccm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection protection));

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId: [0x10, 0x11, 0x12, 0x13],
            sourceConnectionId: [0x20, 0x21],
            packetNumber: [0x01],
            plaintextPayload:
            [
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
                0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
                0x52,
            ]);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.False(protection.TryProtect(plaintextPacket, protectedPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HandshakePacketProtection_RoundTripsRandomValidInputs()
    {
        Random random = new(0x5150_20A7);
        QuicAeadAlgorithm[] algorithms =
        [
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadAlgorithm.Aes128Ccm,
        ];

        for (int iteration = 0; iteration < 32; iteration++)
        {
            QuicAeadAlgorithm algorithm = algorithms[random.Next(algorithms.Length)];
            int aeadKeyLength = algorithm == QuicAeadAlgorithm.Aes256Gcm ? 32 : 16;
            byte[] aeadKey = QuicHeaderTestData.RandomBytes(random, aeadKeyLength);
            byte[] aeadIv = QuicHeaderTestData.RandomBytes(random, 12);
            byte[] headerProtectionKey = QuicHeaderTestData.RandomBytes(random, aeadKeyLength);

            Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
                QuicTlsEncryptionLevel.Handshake,
                algorithm,
                aeadKey,
                aeadIv,
                headerProtectionKey,
                new QuicAeadUsageLimits(64, 128),
                out QuicTlsPacketProtectionMaterial material));

            Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection senderProtection));
            Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection receiverProtection));

            byte[] destinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] sourceConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] packetNumber = QuicHeaderTestData.RandomBytes(random, random.Next(1, 5));
            byte[] plaintextPayload = QuicHeaderTestData.RandomBytes(random, random.Next(20, 65));

            byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
                destinationConnectionId,
                sourceConnectionId,
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

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }
}
