namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP1P1-0002")]
public sealed class REQ_QUIC_RFC9001_SBP1P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryGetUsageLimits_UsesTheLargePacketSizeProfileForGcmConfidentiality()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            QuicAeadPacketSizeProfile.Unrestricted,
            out QuicAeadUsageLimits limits));

        Assert.Equal(8_388_608d, limits.ConfidentialityLimitPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetUsageLimits_RejectsUnrestrictedGcmConfidentialityForTheLargePacketLimit()
    {
        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.Unrestricted,
            QuicAeadPacketSizeProfile.Unrestricted,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGetUsageLimits_LargePacketGcmConfidentialityLimitIsOnlyAvailableForTheLargePacketProfile()
    {
        for (int profileValue = -8; profileValue <= 8; profileValue++)
        {
            QuicAeadPacketSizeProfile profile = (QuicAeadPacketSizeProfile)profileValue;
            bool accepted = QuicAeadUsageLimitCalculator.TryGetUsageLimits(
                QuicAeadAlgorithm.Aes256Gcm,
                profile,
                QuicAeadPacketSizeProfile.Unrestricted,
                out QuicAeadUsageLimits limits);

            if (profile == QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes)
            {
                Assert.True(accepted);
                Assert.Equal(8_388_608d, limits.ConfidentialityLimitPackets);
            }
            else
            {
                Assert.False(accepted && limits.ConfidentialityLimitPackets == 8_388_608d);
            }
        }
    }
}
