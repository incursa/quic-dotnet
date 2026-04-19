namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0003">An endpoint SHOULD use DPLPMTUD or PMTUD to determine whether the path to a destination will support a desired maximum datagram size without fragmentation.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0003")]
public sealed class REQ_QUIC_RFC9000_S14P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSend_DeterminesWhetherThePathSupportsADesiredDatagramSize()
    {
        QuicConnectionPathMaximumDatagramSizeState state = QuicConnectionPathMaximumDatagramSizeState.CreateInitial();

        Assert.True(state.CanSend(QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes));
        Assert.False(state.CanSend(1350));

        QuicConnectionPathMaximumDatagramSizeState updated = state.WithMaximumDatagramSize(1350);

        Assert.True(updated.CanSend(1350));
        Assert.False(updated.CanSend(1351));
    }
}
