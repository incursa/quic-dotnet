namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP1P1-0001")]
public sealed class REQ_QUIC_RFC9001_SBP1P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryGetUsageLimits_UsesTheStrictPacketSizeProfileForGcmConfidentiality()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits));

        Assert.Equal(268_435_456d, limits.ConfidentialityLimitPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetUsageLimits_DoesNotUseTheStrictGcmConfidentialityLimitForLargerPacketProfiles()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits));

        Assert.NotEqual(268_435_456d, limits.ConfidentialityLimitPackets);
        Assert.Equal(8_388_608d, limits.ConfidentialityLimitPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGetUsageLimits_StrictGcmConfidentialityLimitIsOnlyAvailableForTheStrictProfile()
    {
        for (int profileValue = -8; profileValue <= 8; profileValue++)
        {
            QuicAeadPacketSizeProfile profile = (QuicAeadPacketSizeProfile)profileValue;
            bool accepted = QuicAeadUsageLimitCalculator.TryGetUsageLimits(
                QuicAeadAlgorithm.Aes256Gcm,
                profile,
                QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
                out QuicAeadUsageLimits limits);

            if (profile == QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes)
            {
                Assert.True(accepted);
                Assert.Equal(268_435_456d, limits.ConfidentialityLimitPackets);
            }
            else
            {
                Assert.False(accepted && limits.ConfidentialityLimitPackets == 268_435_456d);
            }
        }
    }
}
