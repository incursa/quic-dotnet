namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP1P1-0005">The sent-packet record MUST include the time the packet was sent.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP1P1-0005")]
public sealed class REQ_QUIC_RFC9002_SAP1P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordSendTime_PreservesTheTimestampInThePacketRecord()
    {
        QuicPersistentCongestionPacket earlyPacket = new(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 1_000,
            sentBytes: 1_200,
            ackEliciting: true,
            inFlight: true,
            acknowledged: false,
            lost: true);

        QuicPersistentCongestionPacket laterPacket = new(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: 2_750,
            sentBytes: 1_200,
            ackEliciting: false,
            inFlight: false,
            acknowledged: true,
            lost: false);

        Assert.Equal(1_000UL, earlyPacket.SentAtMicros);
        Assert.Equal(2_750UL, laterPacket.SentAtMicros);
    }
}
