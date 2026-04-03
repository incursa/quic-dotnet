namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP5-0001")]
public sealed class REQ_QUIC_RFC9002_SBP5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryRegisterAcknowledgedPacket_IgnoresPacketsThatAreNotInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.False(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: false));

        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.False(state.HasRecoveryStartTime);
    }
}
