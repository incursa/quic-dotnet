namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7-0002")]
public sealed class REQ_QUIC_RFC9002_S7_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void RegisterPacketSent_CountsNonAckOnlyPacketsTowardBytesInFlight()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200, isAckOnlyPacket: false);

        Assert.Equal(1_200UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void RegisterPacketSent_DoesNotIncreaseBytesInFlightForAckOnlyPacketsAtTheCongestionWindowLimit()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        state.RegisterPacketSent(1_200, isAckOnlyPacket: true);

        Assert.Equal(state.CongestionWindowBytes, state.BytesInFlightBytes);
    }
}
