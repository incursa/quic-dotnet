namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SB-0001")]
public sealed class REQ_QUIC_RFC9001_SB_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetUsageLimits_UsesTheStrictPacketSizeProfileForGcm()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits));

        Assert.Equal(268_435_456d, limits.ConfidentialityLimitPackets);
        Assert.Equal(144_115_188_075_855_872d, limits.IntegrityLimitPackets);
    }
}
