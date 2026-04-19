namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0010">A QUIC implementation MAY be more conservative in computing the maximum datagram size to allow for unknown tunnel overheads or IP header options or extensions.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0010")]
public sealed class REQ_QUIC_RFC9000_S14P2_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySetActivePathMaximumDatagramSize_LeavesOrdinaryPacketsEnabledAtAConservativeEstimateJustAboveTheRfcMinimum()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        ulong conservativeMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes + 1;

        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(conservativeMaximumDatagramSizeBytes));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(conservativeMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets);
        Assert.Equal(conservativeMaximumDatagramSizeBytes, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySetActivePathMaximumDatagramSize_ProjectsAConservativeEstimateOntoTheSendRuntime()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        ulong conservativeMaximumDatagramSizeBytes = 1_350;

        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(conservativeMaximumDatagramSizeBytes));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(conservativeMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSend(conservativeMaximumDatagramSizeBytes));
        Assert.False(runtime.ActivePath.Value.MaximumDatagramSizeState.CanSend(conservativeMaximumDatagramSizeBytes + 1));
        Assert.Equal(conservativeMaximumDatagramSizeBytes, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySetActivePathMaximumDatagramSize_RejectsZeroMaximumDatagramSize()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        ulong initialMaximumDatagramSizeBytes = runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes;

        Assert.Throws<ArgumentOutOfRangeException>(() => runtime.TrySetActivePathMaximumDatagramSize(0));
        Assert.Equal(initialMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.Equal(initialMaximumDatagramSizeBytes, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }
}
