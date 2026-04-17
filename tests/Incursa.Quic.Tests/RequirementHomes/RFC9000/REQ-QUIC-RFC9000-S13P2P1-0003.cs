namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0003">A sender uses the MUST receiver's max_ack_delay value in determining timeouts for timer-based retransmission, as detailed in Section 6.2 of [QUIC-RECOVERY].</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0003")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryComputeProbeTimeoutMicros_UsesTheReceiverMaxAckDelayForApplicationDataPackets()
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
}
