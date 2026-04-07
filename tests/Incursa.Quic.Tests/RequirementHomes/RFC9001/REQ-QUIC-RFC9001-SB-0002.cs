namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SB-0002")]
public sealed class REQ_QUIC_RFC9001_SB_0002
{
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
