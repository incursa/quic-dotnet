namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P3P1-0002")]
public sealed class REQ_QUIC_RFC9002_S7P3P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    public void IsInSlowStartFollowsTheCongestionWindowThresholdRelationship()
    {
        QuicCongestionControlState state = new();

        Assert.True(state.IsInSlowStart);
        Assert.False(state.IsInCongestionAvoidance);

        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true));

        Assert.False(state.IsInSlowStart);
        Assert.True(state.IsInCongestionAvoidance);
        Assert.Equal(state.CongestionWindowBytes, state.SlowStartThresholdBytes);
    }
}
