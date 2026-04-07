namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP1P1-0002")]
public sealed class REQ_QUIC_RFC9001_SBP1P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetUsageLimits_UsesTheLargePacketSizeProfileForGcmConfidentiality()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            QuicAeadPacketSizeProfile.Unrestricted,
            out QuicAeadUsageLimits limits));

        Assert.Equal(8_388_608d, limits.ConfidentialityLimitPackets);
    }
}
