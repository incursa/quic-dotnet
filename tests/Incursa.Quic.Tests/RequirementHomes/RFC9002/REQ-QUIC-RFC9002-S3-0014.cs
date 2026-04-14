namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0014">Packets containing frames besides ACK or CONNECTION_CLOSE MUST count toward congestion control limits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0014")]
public sealed class REQ_QUIC_RFC9002_S3_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RegisterPacketSent_CountsNonAckOnlyPacketsTowardBytesInFlight()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200UL, isAckOnlyPacket: false);

        Assert.Equal(1_200UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RegisterPacketSent_DoesNotCountAckOnlyPacketsTowardBytesInFlight()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200UL, isAckOnlyPacket: true);

        Assert.Equal(0UL, state.BytesInFlightBytes);
    }
}
