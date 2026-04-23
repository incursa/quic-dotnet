namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP1P2-0001")]
public sealed class REQ_QUIC_RFC9001_SBP1P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryGetUsageLimits_UsesTheStrictPacketSizeProfileForGcmIntegrity()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits));

        Assert.Equal(144_115_188_075_855_872d, limits.IntegrityLimitPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetUsageLimits_RejectsLargePacketProfileForGcmIntegrity()
    {
        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGetUsageLimits_StrictGcmIntegrityLimitIsOnlyAvailableForTheStrictProfile()
    {
        for (int profileValue = -8; profileValue <= 8; profileValue++)
        {
            QuicAeadPacketSizeProfile profile = (QuicAeadPacketSizeProfile)profileValue;
            bool accepted = QuicAeadUsageLimitCalculator.TryGetUsageLimits(
                QuicAeadAlgorithm.Aes128Gcm,
                QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
                profile,
                out QuicAeadUsageLimits limits);

            if (profile == QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes)
            {
                Assert.True(accepted);
                Assert.Equal(144_115_188_075_855_872d, limits.IntegrityLimitPackets);
            }
            else
            {
                Assert.False(accepted && limits.IntegrityLimitPackets == 144_115_188_075_855_872d);
            }
        }
    }
}
