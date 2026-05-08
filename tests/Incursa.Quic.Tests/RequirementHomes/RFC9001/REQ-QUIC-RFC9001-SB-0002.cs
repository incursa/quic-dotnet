namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SB-0002")]
public sealed class REQ_QUIC_RFC9001_SB_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryGetUsageLimits_ComputesFiniteConfidentialityAndIntegrityLimitsForSupportedAeads()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits));

        Assert.True(double.IsFinite(limits.ConfidentialityLimitPackets));
        Assert.True(double.IsFinite(limits.IntegrityLimitPackets));
        Assert.True(limits.ConfidentialityLimitPackets > 0d);
        Assert.True(limits.IntegrityLimitPackets > 0d);

        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Chacha20Poly1305,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits chacha20Limits));

        Assert.True(double.IsFinite(chacha20Limits.ConfidentialityLimitPackets));
        Assert.True(double.IsFinite(chacha20Limits.IntegrityLimitPackets));
        Assert.True(chacha20Limits.ConfidentialityLimitPackets > 0d);
        Assert.True(chacha20Limits.IntegrityLimitPackets > 0d);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetUsageLimits_RejectsUnsupportedPolicyCombinations()
    {
        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.Unrestricted,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out _));

        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            out _));

        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.Unrestricted,
            out _));

        Assert.False(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            (QuicAeadAlgorithm)999,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out _));
    }
}
