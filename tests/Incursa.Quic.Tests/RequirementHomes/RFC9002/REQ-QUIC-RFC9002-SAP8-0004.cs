namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP8-0004")]
public sealed class REQ_QUIC_RFC9002_SAP8_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryComputeProbeTimeoutMicros_IncludesMaxAckDelayForApplicationData()
    {
        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 500,
            handshakeConfirmed: true,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 1));

        Assert.Equal(2_500UL, probeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ComputeProbeTimeoutWithBackoffMicros_DoublesTheApplicationDataPtoForEachTimeout()
    {
        Assert.Equal(10_000UL, QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
            probeTimeoutMicros: 2_500,
            ptoCount: 2));
    }
}
