namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP1P1-0001">The sent-packet record MUST include the packet number of the sent packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP1P1-0001")]
public sealed class REQ_QUIC_RFC9002_SAP1P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordPacketNumber_PreservesThePacketNumberInThePacketRecord()
    {
        QuicPersistentCongestionPacket initialPacket = new(
            QuicPacketNumberSpace.Initial,
            sentAtMicros: 1_000,
            sentBytes: 1_200,
            ackEliciting: true,
            inFlight: true,
            acknowledged: false,
            lost: true,
            packetNumber: 41);

        QuicPersistentCongestionPacket applicationDataPacket = new(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 2_000,
            sentBytes: 900,
            ackEliciting: false,
            inFlight: false,
            acknowledged: true,
            lost: false,
            packetNumber: 4_294_967_295UL);

        Assert.Equal(41UL, initialPacket.PacketNumber);
        Assert.Equal(4_294_967_295UL, applicationDataPacket.PacketNumber);
    }
}
