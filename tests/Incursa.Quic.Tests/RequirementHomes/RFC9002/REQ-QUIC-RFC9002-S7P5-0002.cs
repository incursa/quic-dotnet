namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P5-0002")]
public sealed class REQ_QUIC_RFC9002_S7P5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void RegisterPacketSent_CountsProbePacketsAsAdditionalBytesInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.Equal(state.CongestionWindowBytes + 1_200UL, state.BytesInFlightBytes);
    }
}
