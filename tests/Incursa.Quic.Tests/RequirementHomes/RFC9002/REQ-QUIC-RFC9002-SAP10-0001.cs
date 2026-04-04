namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP10-0001">DetectAndRemoveLostPackets MUST only run when largest_acked_packet[pn_space] is known.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP10-0001")]
public sealed class REQ_QUIC_RFC9002_SAP10_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanDeclarePacketLost_AllowsOlderInFlightPacketsWhenTheLargestAcknowledgedPacketIsKnown()
    {
        Assert.True(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 8,
            largestAcknowledgedPacketNumber: 11));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanDeclarePacketLost_ReturnsFalseWhenTheCandidatePacketIsNotOlderThanTheLargestAcknowledgedPacket()
    {
        Assert.False(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 11,
            largestAcknowledgedPacketNumber: 11));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanDeclarePacketLost_UsesTheLowestPacketNumberBoundary()
    {
        Assert.True(QuicRecoveryTiming.CanDeclarePacketLost(
            packetAcknowledged: false,
            packetInFlight: true,
            packetNumber: 0,
            largestAcknowledgedPacketNumber: 1));
    }
}
