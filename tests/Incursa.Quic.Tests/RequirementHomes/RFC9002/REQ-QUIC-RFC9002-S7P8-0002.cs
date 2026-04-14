namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P8-0002">A sender SHOULD NOT consider itself application limited if it would have fully utilized the congestion window without pacing delay.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P8-0002")]
public sealed class REQ_QUIC_RFC9002_S7P8_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_GrowsTheCongestionWindowWhenPacingDelayWouldHaveMaskedUtilization()
    {
        QuicSenderFlowController sender = new();

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = 1,
            AckDelay = 100,
            FirstAckRange = 0,
            AdditionalRanges = Array.Empty<QuicAckRange>(),
        };

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pacingLimited: true));

        Assert.Equal(0UL, sender.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(13_200UL, sender.CongestionControlState.CongestionWindowBytes);
        Assert.False(sender.CongestionControlState.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_DoesNotGrowTheCongestionWindowWhenApplicationLimitedIsSet()
    {
        QuicSenderFlowController sender = new();

        sender.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = 1,
            AckDelay = 100,
            FirstAckRange = 0,
            AdditionalRanges = Array.Empty<QuicAckRange>(),
        };

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            applicationLimited: true,
            pacingLimited: true));

        Assert.Equal(0UL, sender.CongestionControlState.BytesInFlightBytes);
        Assert.Equal(12_000UL, sender.CongestionControlState.CongestionWindowBytes);
        Assert.False(sender.CongestionControlState.HasRecoveryStartTime);
    }
}
