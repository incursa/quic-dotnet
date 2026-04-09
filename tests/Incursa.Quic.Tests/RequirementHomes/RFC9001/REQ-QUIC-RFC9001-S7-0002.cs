namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S7-0002")]
public sealed class REQ_QUIC_RFC9001_S7_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenHandshakePacket_RejectsMalformedCryptoFramePayloads()
    {
        QuicTlsPacketProtectionMaterial material = CreateHandshakeMaterial();
        byte[] malformedPayload = CreateMalformedCryptoPayload();

        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection senderProtection));

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId: [],
            sourceConnectionId: [],
            packetNumber: [0x01, 0x02, 0x03, 0x04],
            plaintextPayload: malformedPayload);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenHandshakePacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.False(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out _,
            out _));
    }

    private static byte[] CreateMalformedCryptoPayload()
    {
        byte[] payload = new byte[24];
        payload[0] = 0x06;
        payload[1] = 0x00;
        payload[2] = 0x1E;
        payload[3] = 0xAA;
        payload[4] = 0xBB;
        return payload;
    }

    private static QuicTlsPacketProtectionMaterial CreateHandshakeMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
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
