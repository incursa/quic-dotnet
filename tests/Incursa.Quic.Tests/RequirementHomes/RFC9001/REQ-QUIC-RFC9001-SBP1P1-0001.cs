namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP1P1-0001")]
public sealed class REQ_QUIC_RFC9001_SBP1P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetUsageLimits_UsesTheStrictPacketSizeProfileForGcmConfidentiality()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits));

        Assert.Equal(268_435_456d, limits.ConfidentialityLimitPackets);
    }
}
