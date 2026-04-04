namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P4-0009")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryDeclareInFlightPacketsLostInsteadOfProbing_UsesLossRegistration()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
    }
}
