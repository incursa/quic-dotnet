namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P4-0005")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryIncludeNewDataInPtoProbes_AllowsProbePacketsToCarryPayload()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.True(state.CanSend(1_200, isProbePacket: true));

        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.Equal(state.CongestionWindowBytes + 1_200UL, state.BytesInFlightBytes);
    }
}
