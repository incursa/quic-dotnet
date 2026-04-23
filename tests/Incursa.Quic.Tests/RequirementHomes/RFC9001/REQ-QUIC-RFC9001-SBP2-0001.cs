namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP2-0001")]
public sealed class REQ_QUIC_RFC9001_SBP2_0001
{
    [Theory]
    [InlineData(0, 26.5d)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryGetUsageLimits_UsesTheStrictPacketSizeProfileForCcm(
        int packetSizeProfileValue,
        double expectedLog2PacketLimit)
    {
        QuicAeadPacketSizeProfile packetSizeProfile = (QuicAeadPacketSizeProfile)packetSizeProfileValue;
        double expectedLimitPackets = Math.Pow(2d, expectedLog2PacketLimit);

        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            packetSizeProfile,
            packetSizeProfile,
            out QuicAeadUsageLimits limits));

        Assert.InRange(Math.Abs(expectedLimitPackets - limits.ConfidentialityLimitPackets), 0d, 1e-9d);
        Assert.InRange(Math.Abs(expectedLimitPackets - limits.IntegrityLimitPackets), 0d, 1e-9d);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetUsageLimits_RejectsMismatchedCcmProfilesForStrictPacketLimits()
    {
        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.Unrestricted,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGetUsageLimits_StrictCcmLimitIsOnlyAvailableForMatchedStrictProfiles()
    {
        double expectedLimitPackets = Math.Pow(2d, 26.5d);

        for (int confidentialityProfileValue = -4; confidentialityProfileValue <= 4; confidentialityProfileValue++)
        {
            for (int integrityProfileValue = -4; integrityProfileValue <= 4; integrityProfileValue++)
            {
                QuicAeadPacketSizeProfile confidentialityProfile = (QuicAeadPacketSizeProfile)confidentialityProfileValue;
                QuicAeadPacketSizeProfile integrityProfile = (QuicAeadPacketSizeProfile)integrityProfileValue;
                bool accepted = QuicAeadUsageLimitCalculator.TryGetUsageLimits(
                    QuicAeadAlgorithm.Aes128Ccm,
                    confidentialityProfile,
                    integrityProfile,
                    out QuicAeadUsageLimits limits);

                if (confidentialityProfile == QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes
                    && integrityProfile == QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes)
                {
                    Assert.True(accepted);
                    Assert.InRange(Math.Abs(expectedLimitPackets - limits.ConfidentialityLimitPackets), 0d, 1e-9d);
                    Assert.InRange(Math.Abs(expectedLimitPackets - limits.IntegrityLimitPackets), 0d, 1e-9d);
                }
                else
                {
                    Assert.False(accepted && Math.Abs(expectedLimitPackets - limits.ConfidentialityLimitPackets) <= 1e-9d);
                }
            }
        }
    }
}
