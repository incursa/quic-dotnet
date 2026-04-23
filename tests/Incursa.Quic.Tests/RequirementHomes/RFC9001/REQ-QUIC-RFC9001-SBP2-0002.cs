namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP2-0002")]
public sealed class REQ_QUIC_RFC9001_SBP2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryGetUsageLimits_UsesTheUnrestrictedPacketSizeProfileForCcm()
    {
        double expectedLimitPackets = Math.Pow(2d, 21.5d);

        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            QuicAeadPacketSizeProfile.Unrestricted,
            QuicAeadPacketSizeProfile.Unrestricted,
            out QuicAeadUsageLimits limits));

        Assert.InRange(Math.Abs(expectedLimitPackets - limits.ConfidentialityLimitPackets), 0d, 1e-9d);
        Assert.InRange(Math.Abs(expectedLimitPackets - limits.IntegrityLimitPackets), 0d, 1e-9d);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetUsageLimits_RejectsMismatchedCcmProfilesForUnrestrictedPacketLimits()
    {
        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            QuicAeadPacketSizeProfile.Unrestricted,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGetUsageLimits_UnrestrictedCcmLimitIsOnlyAvailableForMatchedUnrestrictedProfiles()
    {
        double expectedLimitPackets = Math.Pow(2d, 21.5d);

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

                if (confidentialityProfile == QuicAeadPacketSizeProfile.Unrestricted
                    && integrityProfile == QuicAeadPacketSizeProfile.Unrestricted)
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
