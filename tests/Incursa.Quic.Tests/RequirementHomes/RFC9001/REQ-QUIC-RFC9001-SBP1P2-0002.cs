namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP1P2-0002")]
public sealed class REQ_QUIC_RFC9001_SBP1P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryGetUsageLimits_UsesTheLargePacketSizeProfileForGcmIntegrity()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            QuicAeadPacketSizeProfile.Unrestricted,
            out QuicAeadUsageLimits limits));

        Assert.Equal(4_503_599_627_370_496d, limits.IntegrityLimitPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetUsageLimits_DoesNotUseTheUnrestrictedGcmIntegrityLimitForStrictIntegrityProfiles()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits));

        Assert.NotEqual(4_503_599_627_370_496d, limits.IntegrityLimitPackets);
        Assert.Equal(144_115_188_075_855_872d, limits.IntegrityLimitPackets);
    }
}
