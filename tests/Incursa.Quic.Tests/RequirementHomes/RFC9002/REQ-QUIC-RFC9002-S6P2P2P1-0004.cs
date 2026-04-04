namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0004")]
public sealed class REQ_QUIC_RFC9002_S6P2P2P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryComputeProbeTimeoutMicros_ArmsHandshakePtoBeforeHandshakeConfirmation()
    {
        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.Handshake,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 500,
            handshakeConfirmed: false,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 1));

        Assert.Equal(2_000UL, probeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryComputeProbeTimeoutMicros_DoesNotArmApplicationDataBeforeHandshakeConfirmation()
    {
        Assert.False(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 500,
            handshakeConfirmed: false,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryComputeProbeTimeoutMicros_ArmsHandshakePtoAtTheGranularityFloorWhenRttIsZero()
    {
        Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.Handshake,
            smoothedRttMicros: 0,
            rttVarMicros: 0,
            maxAckDelayMicros: 500,
            handshakeConfirmed: false,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 1));

        Assert.Equal(1UL, probeTimeoutMicros);
    }
}
