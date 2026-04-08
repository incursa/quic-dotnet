namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P3P1-0003">While a sender is in slow start, the congestion window MUST increase by the number of bytes acknowledged when each acknowledgment is processed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P3P1-0003")]
public sealed class REQ_QUIC_RFC9002_S7P3P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterAcknowledgedPacket_GrowsTheCongestionWindowByAckedBytesInSlowStart()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: true));

        Assert.Equal(13_200UL, state.CongestionWindowBytes);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.True(state.IsInSlowStart);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SenderFlowController_UsesAckFramesToAcknowledgeAndGrowTheCongestionWindowInSlowStart()
    {
        QuicSenderFlowController sender = new();

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            sentBytes: 1_200,
            sentAtMicros: 1_100,
            ackEliciting: true);

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 3,
            sentBytes: 1_200,
            sentAtMicros: 1_200,
            ackEliciting: true);

        Assert.Equal(3_600UL, sender.CongestionControlState.BytesInFlightBytes);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = 3,
            AckDelay = 100,
            FirstAckRange = 2,
            AdditionalRanges = Array.Empty<QuicAckRange>(),
        };

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pacingLimited: true));

        Assert.Equal(0UL, sender.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(15_600UL, sender.CongestionControlState.CongestionWindowBytes);
        Assert.True(sender.CongestionControlState.IsInSlowStart);
    }
}
