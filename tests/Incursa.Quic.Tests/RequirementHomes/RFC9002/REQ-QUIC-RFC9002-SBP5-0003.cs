namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP5-0003")]
public sealed class REQ_QUIC_RFC9002_SBP5_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SBP5-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterAcknowledgedPacket_DoesNotGrowTheWindowWhenApplicationOrFlowControlLimited()
    {
        QuicCongestionControlState applicationLimitedState = new();
        applicationLimitedState.RegisterPacketSent(12_000);
        applicationLimitedState.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(applicationLimitedState.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            applicationLimited: true));

        Assert.Equal(12_000UL, applicationLimitedState.BytesInFlightBytes);
        Assert.Equal(12_000UL, applicationLimitedState.CongestionWindowBytes);

        QuicCongestionControlState flowControlLimitedState = new();
        flowControlLimitedState.RegisterPacketSent(12_000);
        flowControlLimitedState.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(flowControlLimitedState.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            flowControlLimited: true));

        Assert.Equal(12_000UL, flowControlLimitedState.BytesInFlightBytes);
        Assert.Equal(12_000UL, flowControlLimitedState.CongestionWindowBytes);
    }
}
