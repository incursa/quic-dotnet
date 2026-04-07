namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP1P2-0002")]
public sealed class REQ_QUIC_RFC9001_SBP1P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetUsageLimits_UsesTheLargePacketSizeProfileForGcmIntegrity()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            QuicAeadPacketSizeProfile.Unrestricted,
            out QuicAeadUsageLimits limits));

        Assert.Equal(4_503_599_627_370_496d, limits.IntegrityLimitPackets);
    }
}
