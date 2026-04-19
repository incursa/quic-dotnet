namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0005">Both DPLPMTUD and PMTUD MUST send datagrams that are larger than the current maximum datagram size, referred to as PMTU probes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0005")]
public sealed class REQ_QUIC_RFC9000_S14P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CanSend_AllowsProbePacketsToExceedTheCurrentMaximumDatagramSize()
    {
        QuicConnectionPathMaximumDatagramSizeState state = QuicConnectionPathMaximumDatagramSizeState.CreateInitial();

        Assert.True(state.CanSend(1350, isProbePacket: true));
        Assert.False(state.CanSend(1350));
        Assert.False(state.CanSend(QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes, isProbePacket: true));
    }
}
