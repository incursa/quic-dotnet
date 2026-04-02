namespace Incursa.Quic.Tests;

public sealed class QuicAeadUsageLimitCalculatorTests
{
    [Theory]
    [InlineData(QuicAeadAlgorithm.Aes128Gcm, QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, 268_435_456d, 144_115_188_075_855_872d)]
    [InlineData(QuicAeadAlgorithm.Aes256Gcm, QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, 268_435_456d, 144_115_188_075_855_872d)]
    [InlineData(QuicAeadAlgorithm.Aes256Gcm, QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes, QuicAeadPacketSizeProfile.Unrestricted, 8_388_608d, 4_503_599_627_370_496d)]
    [Requirement("REQ-QUIC-RFC9001-SB-0001")]
    [Requirement("REQ-QUIC-RFC9001-SB-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P1-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P1-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0002")]
    [Trait("Category", "Positive")]
    public void TryGetUsageLimits_RespectsTheGcmPacketSizeThresholds(
        QuicAeadAlgorithm algorithm,
        QuicAeadPacketSizeProfile confidentialityPacketSizeProfile,
        QuicAeadPacketSizeProfile integrityPacketSizeProfile,
        double expectedConfidentialityLimitPackets,
        double expectedIntegrityLimitPackets)
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            algorithm,
            confidentialityPacketSizeProfile,
            integrityPacketSizeProfile,
            out QuicAeadUsageLimits limits));

        AssertApproximatelyEqual(expectedConfidentialityLimitPackets, limits.ConfidentialityLimitPackets);
        AssertApproximatelyEqual(expectedIntegrityLimitPackets, limits.IntegrityLimitPackets);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0003")]
    [Trait("Category", "Positive")]
    public void TryGetUsageLimits_UsesTheSameIntegrityLimitForAes128AndAes256Gcm()
    {
        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits aes128Limits));

        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits aes256Limits));

        AssertApproximatelyEqual(aes128Limits.IntegrityLimitPackets, aes256Limits.IntegrityLimitPackets);
    }

    [Theory]
    [InlineData(QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, 26.5d)]
    [InlineData(QuicAeadPacketSizeProfile.Unrestricted, 21.5d)]
    [Requirement("REQ-QUIC-RFC9001-SB-0001")]
    [Requirement("REQ-QUIC-RFC9001-SB-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP2-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP2-0002")]
    [Trait("Category", "Positive")]
    public void TryGetUsageLimits_UsesTheCcmPacketSizeThresholds(
        QuicAeadPacketSizeProfile packetSizeProfile,
        double expectedLog2PacketLimit)
    {
        double expectedLimitPackets = Math.Pow(2d, expectedLog2PacketLimit);

        Assert.True(QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            packetSizeProfile,
            packetSizeProfile,
            out QuicAeadUsageLimits limits));

        AssertApproximatelyEqual(expectedLimitPackets, limits.ConfidentialityLimitPackets);
        AssertApproximatelyEqual(expectedLimitPackets, limits.IntegrityLimitPackets);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-SB-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P1-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P1-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP2-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP2-0002")]
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

    private static void AssertApproximatelyEqual(double expected, double actual)
    {
        Assert.InRange(Math.Abs(expected - actual), 0d, 1e-9d);
    }
}
