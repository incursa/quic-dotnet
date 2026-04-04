namespace Incursa.Quic.Tests;

public sealed class QuicAeadUsageLimitCalculatorTests
{
    [Theory]
    [InlineData(QuicAeadAlgorithm.Aes128Gcm, QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, 268_435_456d, 144_115_188_075_855_872d)]
    [InlineData(QuicAeadAlgorithm.Aes256Gcm, QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes, 268_435_456d, 144_115_188_075_855_872d)]
    [InlineData(QuicAeadAlgorithm.Aes256Gcm, QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes, QuicAeadPacketSizeProfile.Unrestricted, 8_388_608d, 4_503_599_627_370_496d)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SB-0001">Only endpoints that strictly limit packet size MAY use the larger confidentiality and integrity limits derived using the smaller packet size.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SB-0002">Any AEAD that is used with QUIC MUST have limits on use that ensure that both confidentiality and integrity are preserved.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P1-0001">Endpoints that do not send packets larger than 2^11 bytes MUST NOT protect more than 2^28 packets in a single connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P1-0002">Endpoints that allow packets as large as 2^16 bytes MUST NOT protect more than 2^23 packets in a single connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P2-0001">Endpoints that do not attempt to remove protection from packets larger than 2^11 bytes MUST NOT attempt to remove protection from more than 2^57 packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P2-0002">Endpoints that do not restrict the size of processed packets MUST NOT attempt to remove protection from more than 2^52 packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-SB-0001")]
    [Requirement("REQ-QUIC-RFC9001-SB-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P1-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P1-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P2-0003">The same integrity limit SHOULD be applied to AEAD_AES_128_GCM and AEAD_AES_256_GCM.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SB-0001">Only endpoints that strictly limit packet size MAY use the larger confidentiality and integrity limits derived using the smaller packet size.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SB-0002">Any AEAD that is used with QUIC MUST have limits on use that ensure that both confidentiality and integrity are preserved.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP2-0001">Endpoints that limit packets to 2^11 bytes MUST have both confidentiality and integrity limits of 2^26.5 packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP2-0002">Endpoints that do not restrict packet size MUST have a limit of 2^21.5 packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-SB-0001")]
    [Requirement("REQ-QUIC-RFC9001-SB-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP2-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SB-0002">Any AEAD that is used with QUIC MUST have limits on use that ensure that both confidentiality and integrity are preserved.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P1-0001">Endpoints that do not send packets larger than 2^11 bytes MUST NOT protect more than 2^28 packets in a single connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P1-0002">Endpoints that allow packets as large as 2^16 bytes MUST NOT protect more than 2^23 packets in a single connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P2-0001">Endpoints that do not attempt to remove protection from packets larger than 2^11 bytes MUST NOT attempt to remove protection from more than 2^57 packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP1P2-0002">Endpoints that do not restrict the size of processed packets MUST NOT attempt to remove protection from more than 2^52 packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP2-0001">Endpoints that limit packets to 2^11 bytes MUST have both confidentiality and integrity limits of 2^26.5 packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-SBP2-0002">Endpoints that do not restrict packet size MUST have a limit of 2^21.5 packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-SB-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P1-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P1-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP1P2-0002")]
    [Requirement("REQ-QUIC-RFC9001-SBP2-0001")]
    [Requirement("REQ-QUIC-RFC9001-SBP2-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
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
