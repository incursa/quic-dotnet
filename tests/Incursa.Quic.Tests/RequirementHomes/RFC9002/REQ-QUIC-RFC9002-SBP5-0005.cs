namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP5-0005">While in slow start, the sender MUST increase congestion_window by the number of acknowledged bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP5-0005")]
public sealed class REQ_QUIC_RFC9002_SBP5_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterAcknowledgedPacket_GrowsTheWindowByAckedBytesInSlowStart()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.Equal(13_200UL, state.CongestionWindowBytes);
    }
}
