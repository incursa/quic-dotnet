namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP10-0004">DetectAndRemoveLostPackets MUST ignore packets whose packet number is greater than largest_acked_packet[pn_space].</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP10-0004")]
public sealed class REQ_QUIC_RFC9002_SAP10_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanDeclarePacketLost_ContinuesEvaluatingPacketsBeforeTheLargestAcknowledgedPacket()
    {
        Assert.True(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 9,
            largestAcknowledgedPacketNumber: 11));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanDeclarePacketLost_IgnoresPacketsBeyondTheLargestAcknowledgedPacket()
    {
        Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 12,
            largestAcknowledgedPacketNumber: 11));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanDeclarePacketLost_IgnoresTheFirstPacketPastTheLargestAcknowledgedBoundary()
    {
        Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 10,
            largestAcknowledgedPacketNumber: 9));
    }
}
