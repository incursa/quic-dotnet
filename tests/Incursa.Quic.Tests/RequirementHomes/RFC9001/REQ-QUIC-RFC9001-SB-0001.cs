namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SB-0001")]
public sealed class REQ_QUIC_RFC9001_SB_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetUsageLimits_RejectsTheLargerGcmConfidentialityLimitWithoutStrictPacketSizeLimiting()
    {
        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.Unrestricted,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGetUsageLimits_DoesNotGrantTheLargestGcmConfidentialityLimitOutsideTheStrictProfile()
    {
        for (int profileValue = -8; profileValue <= 8; profileValue++)
        {
            QuicAeadPacketSizeProfile profile = (QuicAeadPacketSizeProfile)profileValue;
            bool accepted = QuicAeadUsageLimitCalculator.TryGetUsageLimits(
                QuicAeadAlgorithm.Aes128Gcm,
                profile,
                QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
                out QuicAeadUsageLimits limits);

            if (profile == QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes)
            {
                Assert.True(accepted);
                Assert.Equal(268_435_456d, limits.ConfidentialityLimitPackets);
            }
            else if (profile == QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes)
            {
                Assert.True(accepted);
                Assert.Equal(8_388_608d, limits.ConfidentialityLimitPackets);
            }
            else
            {
                Assert.False(accepted);
            }
        }
    }
}
