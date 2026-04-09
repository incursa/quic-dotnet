namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0004")]
public sealed class REQ_QUIC_RFC9001_S4_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenHandshakePacket_RejectsWrongPacketProtectionMaterial()
    {
        QuicTlsPacketProtectionMaterial senderMaterial = CreateHandshakeMaterial(0x11, 0x21, 0x31);
        QuicTlsPacketProtectionMaterial receiverMaterial = CreateHandshakeMaterial(0x41, 0x51, 0x61);
        byte[] protectedPacket = BuildProtectedHandshakePacket(senderMaterial);

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.False(coordinator.TryOpenHandshakePacket(
            protectedPacket,
            receiverMaterial,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenHandshakePacket_RejectsTamperedProtectedPacket()
    {
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial(0x11, 0x21, 0x31);
        byte[] protectedPacket = BuildProtectedHandshakePacket(material);
        protectedPacket[^1] ^= 0x80;

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.False(coordinator.TryOpenHandshakePacket(
            protectedPacket,
            material,
            out _,
            out _,
            out _));
    }

    private static byte[] BuildProtectedHandshakePacket(QuicTlsPacketProtectionMaterial material)
    {
        byte[] cryptoData = CreateSequentialBytes(0x40, 24);
        Span<byte> cryptoFrameBuffer = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(0, cryptoData),
            cryptoFrameBuffer,
            out int cryptoFrameBytesWritten));

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId: [],
            sourceConnectionId: [],
            packetNumber: [0x01, 0x02, 0x03, 0x04],
            plaintextPayload: cryptoFrameBuffer[..cryptoFrameBytesWritten]);

        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection senderProtection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);
        return protectedPacket;
    }

    private static QuicTlsPacketProtectionMaterial CreateHandshakeMaterial(
        byte keySeed,
        byte ivSeed,
        byte hpSeed)
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(keySeed, 16),
            CreateSequentialBytes(ivSeed, 12),
            CreateSequentialBytes(hpSeed, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        return material;
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
