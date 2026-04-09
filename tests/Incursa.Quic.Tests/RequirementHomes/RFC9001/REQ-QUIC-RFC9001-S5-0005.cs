namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0005")]
public sealed class REQ_QUIC_RFC9001_S5_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryCreate_UsesAes128GcmForInitialPackets()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08],
            out QuicInitialPacketProtection protection));

        Assert.Equal(QuicAeadAlgorithm.Aes128Gcm, protection.OutboundMaterial.Algorithm);
        Assert.Equal(QuicAeadAlgorithm.Aes128Gcm, protection.InboundMaterial.Algorithm);
        Assert.Equal(QuicInitialPacketProtection.AeadKeyLength, protection.OutboundMaterial.AeadKey.Length);
        Assert.Equal(QuicInitialPacketProtection.AeadNonceLength, protection.OutboundMaterial.AeadIv.Length);
        Assert.Equal(QuicInitialPacketProtection.HeaderProtectionKeyLength, protection.OutboundMaterial.HeaderProtectionKey.Length);
        Assert.Equal(QuicInitialPacketProtection.AeadKeyLength, protection.InboundMaterial.AeadKey.Length);
        Assert.Equal(QuicInitialPacketProtection.AeadNonceLength, protection.InboundMaterial.AeadIv.Length);
        Assert.Equal(QuicInitialPacketProtection.HeaderProtectionKeyLength, protection.InboundMaterial.HeaderProtectionKey.Length);
    }
}
