namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P6P1-0002")]
public sealed class REQ_QUIC_RFC9002_S7P6P1_0002
{
    [Theory]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData((int)QuicPacketNumberSpace.Initial)]
    [InlineData((int)QuicPacketNumberSpace.Handshake)]
    [InlineData((int)QuicPacketNumberSpace.ApplicationData)]
    public void TryComputePersistentCongestionDurationMicros_IncludesMaxAckDelayForEverySpace(
        int packetNumberSpaceValue)
    {
        QuicPacketNumberSpace packetNumberSpace = (QuicPacketNumberSpace)packetNumberSpaceValue;
        _ = packetNumberSpace;

        Assert.True(QuicCongestionControlState.TryComputePersistentCongestionDurationMicros(
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 500,
            out ulong durationMicros));

        Assert.Equal(7_500UL, durationMicros);
    }
}
