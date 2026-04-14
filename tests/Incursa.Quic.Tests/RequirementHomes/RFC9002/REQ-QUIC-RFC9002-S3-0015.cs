namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0015">Packets containing frames besides ACK or CONNECTION_CLOSE MUST be considered in flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S3-0015")]
public sealed class REQ_QUIC_RFC9002_S3_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordPacketSent_RetainsNonAckOnlyPacketsInTheSentPacketSet()
    {
        QuicSenderRecoveryRuntime runtime = new();

        runtime.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            sentBytes: 1_200UL,
            sentAtMicros: 1_000UL,
            ackEliciting: false,
            isAckOnlyPacket: false);

        Assert.Equal(1_200UL, runtime.SenderFlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(1, runtime.PendingSentPacketCount);
        Assert.True(runtime.TryGetSentPacket(QuicPacketNumberSpace.ApplicationData, 7, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordPacketSent_DoesNotTrackAckOnlyPacketsAsInFlight()
    {
        QuicSenderRecoveryRuntime runtime = new();

        runtime.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 8,
            sentBytes: 1_200UL,
            sentAtMicros: 1_500UL,
            ackEliciting: false,
            isAckOnlyPacket: true);

        Assert.Equal(0UL, runtime.SenderFlowController.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(0, runtime.PendingSentPacketCount);
        Assert.False(runtime.TryGetSentPacket(QuicPacketNumberSpace.ApplicationData, 8, out _));
    }
}
