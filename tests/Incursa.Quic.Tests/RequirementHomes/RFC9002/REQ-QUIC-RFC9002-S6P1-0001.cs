namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P1-0001")]
public sealed class REQ_QUIC_RFC9002_S6P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanDeclarePacketLost_AllowsAnUnacknowledgedInflightPacketSentBeforeTheLargestAcknowledgedPacket()
    {
        Assert.True(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 9,
            largestAcknowledgedPacketNumber: 11));
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanDeclarePacketLost_RejectsPacketsThatAreAcknowledgedOrNotInFlight(
        bool packetAcknowledged,
        bool packetInFlight)
    {
        Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged,
            packetInFlight,
            packetNumber: 9,
            largestAcknowledgedPacketNumber: 11));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanDeclarePacketLost_RejectsPacketsAtTheLargestAcknowledgedBoundary()
    {
        Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 11,
            largestAcknowledgedPacketNumber: 11));
    }
}
