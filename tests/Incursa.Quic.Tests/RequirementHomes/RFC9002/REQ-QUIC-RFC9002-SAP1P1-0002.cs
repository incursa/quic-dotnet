namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP1P1-0002">The sent-packet record MUST include a Boolean that indicates whether the packet is ack-eliciting.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP1P1-0002")]
public sealed class REQ_QUIC_RFC9002_SAP1P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordAckElicitingStatus_PreservesTheBooleanValueInThePacketRecord()
    {
        QuicPersistentCongestionPacket ackElicitingPacket = new(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_000,
            sentBytes: 1_200,
            ackEliciting: true,
            inFlight: true,
            acknowledged: false,
            lost: false);

        QuicPersistentCongestionPacket nonAckElicitingPacket = new(
            QuicPacketNumberSpace.Handshake,
            sentAtMicros: 2_000,
            sentBytes: 900,
            ackEliciting: false,
            inFlight: false,
            acknowledged: true,
            lost: true);

        Assert.True(ackElicitingPacket.AckEliciting);
        Assert.False(nonAckElicitingPacket.AckEliciting);
    }
}
