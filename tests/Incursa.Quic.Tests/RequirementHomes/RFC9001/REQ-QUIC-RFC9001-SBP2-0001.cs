namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-SBP2-0001")]
public sealed class REQ_QUIC_RFC9001_SBP2_0001
{
    [Theory]
    [InlineData(0, 26.5d)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
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
}
