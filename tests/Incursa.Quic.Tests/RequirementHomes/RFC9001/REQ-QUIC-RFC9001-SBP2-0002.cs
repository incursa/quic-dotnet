namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP2-0002")]
public sealed class REQ_QUIC_RFC9001_SBP2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
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
}
