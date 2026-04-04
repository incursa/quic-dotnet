namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP4-0001")]
public sealed class REQ_QUIC_RFC9002_SBP4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RegisterPacketSent_IncreasesBytesInFlightForNonAckPackets()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200, isAckOnlyPacket: false);

        Assert.Equal(1_200UL, state.BytesInFlightBytes);
    }
}
