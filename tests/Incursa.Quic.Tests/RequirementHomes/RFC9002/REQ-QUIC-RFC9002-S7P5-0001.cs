namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P5-0001">Probe packets MUST NOT be blocked by the congestion controller.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P5-0001")]
public sealed class REQ_QUIC_RFC9002_S7P5_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    public void CanSend_StillAllowsProbePacketsWhenTheCongestionWindowIsFull()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.False(state.CanSend(1, isAckOnlyPacket: false, isProbePacket: false));
        Assert.True(state.CanSend(1, isProbePacket: true));
    }
}
