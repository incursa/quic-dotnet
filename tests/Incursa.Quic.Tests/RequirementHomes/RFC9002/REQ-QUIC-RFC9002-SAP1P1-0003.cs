namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP1P1-0003">The sent-packet record MUST include a Boolean that indicates whether the packet counts toward bytes in flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP1P1-0003")]
public sealed class REQ_QUIC_RFC9002_SAP1P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordInFlightStatus_PreservesTheFlightFlagInThePacketRecord()
    {
        QuicPersistentCongestionPacket inFlightPacket = new(
            QuicPacketNumberSpace.Initial,
            sentAtMicros: 1_500,
            sentBytes: 1_200,
            ackEliciting: true,
            inFlight: true,
            acknowledged: false,
            lost: true);

        QuicPersistentCongestionPacket notInFlightPacket = new(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 2_500,
            sentBytes: 900,
            ackEliciting: false,
            inFlight: false,
            acknowledged: true,
            lost: false);

        Assert.True(inFlightPacket.InFlight);
        Assert.False(notInFlightPacket.InFlight);
    }
}
