namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2P1-0004">The client MUST set the PTO timer if it has not received an acknowledgment for any of its Handshake packets and the handshake is not confirmed, even if there are no packets in flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0004")]
public sealed class REQ_QUIC_RFC9002_S6P2P2P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
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
    [Trait("Category", "Negative")]
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
    [Trait("Category", "Edge")]
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
