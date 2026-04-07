namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP1P2-0003")]
public sealed class REQ_QUIC_RFC9001_SBP1P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetUsageLimits_UsesTheSameIntegrityLimitForAes128AndAes256Gcm()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits aes128Limits));

        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits aes256Limits));

        Assert.Equal(aes128Limits.IntegrityLimitPackets, aes256Limits.IntegrityLimitPackets);
    }
}
