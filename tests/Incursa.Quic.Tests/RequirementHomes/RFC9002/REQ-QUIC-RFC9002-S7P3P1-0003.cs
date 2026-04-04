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
}
