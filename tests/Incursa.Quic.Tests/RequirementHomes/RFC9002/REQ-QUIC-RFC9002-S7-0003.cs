namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7-0003")]
public sealed class REQ_QUIC_RFC9002_S7_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void CanSend_RejectsCongestionControlledPacketsThatWouldExceedTheWindow()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.False(state.CanSend(1, isAckOnlyPacket: false, isProbePacket: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void CanSend_AllowsAckOnlyPacketsEvenWhenBytesInFlightMatchesTheCongestionWindow()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.True(state.CanSend(1_200, isAckOnlyPacket: true, isProbePacket: false));
    }
}
