namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0001")]
public sealed class REQ_QUIC_RFC9001_S5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreate_AcceptsHandshakeMaterialWithTheExpectedAeadBinding()
    {
        byte[] aeadKey = CreateSequentialBytes(0x10, 32);
        byte[] aeadIv = CreateSequentialBytes(0x40, 12);
        byte[] headerProtectionKey = CreateSequentialBytes(0x80, 32);

        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes256Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        aeadKey[0] = 0xFF;
        aeadIv[0] = 0xEE;
        headerProtectionKey[0] = 0xDD;

        Assert.Equal(QuicTlsEncryptionLevel.Handshake, material.EncryptionLevel);
        Assert.Equal(QuicAeadAlgorithm.Aes256Gcm, material.Algorithm);
        Assert.Equal(64d, material.UsageLimits.ConfidentialityLimitPackets);
        Assert.Equal(128d, material.UsageLimits.IntegrityLimitPackets);
        Assert.Equal(32, material.AeadKey.Length);
        Assert.Equal(12, material.AeadIv.Length);
        Assert.Equal(32, material.HeaderProtectionKey.Length);
        Assert.True(CreateSequentialBytes(0x10, 32).AsSpan().SequenceEqual(material.AeadKey));
        Assert.True(CreateSequentialBytes(0x40, 12).AsSpan().SequenceEqual(material.AeadIv));
        Assert.True(CreateSequentialBytes(0x80, 32).AsSpan().SequenceEqual(material.HeaderProtectionKey));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreate_RejectsInitialEncryptionLevelAndLengthInvalidMaterial()
    {
        Assert.False(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Initial,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x10, 16),
            CreateSequentialBytes(0x20, 12),
            CreateSequentialBytes(0x30, 16),
            new QuicAeadUsageLimits(64, 128),
            out _));

        Assert.False(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x10, 15),
            CreateSequentialBytes(0x20, 12),
            CreateSequentialBytes(0x30, 16),
            new QuicAeadUsageLimits(64, 128),
            out _));
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
