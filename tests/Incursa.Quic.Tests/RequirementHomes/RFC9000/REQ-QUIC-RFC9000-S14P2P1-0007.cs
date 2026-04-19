namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P2P1-0007")]
public sealed class REQ_QUIC_RFC9000_S14P2P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_AllowsAProvisionalReductionOnTheActivePath()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);

        Assert.True(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            quotedPacket,
            1_300));
        Assert.Equal(1_300UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        Assert.Equal(1_300UL, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Transition_AppliesAProvisionalReductionWhenTheRuntimeReceivesTheICMPEvent()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionIcmpMaximumDatagramSizeReductionEvent(
                ObservedAtTicks: 20,
                runtime.ActivePath!.Value.Identity,
                quotedPacket,
                1_300),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionEventKind.IcmpMaximumDatagramSizeReduction, result.EventKind);
        Assert.Equal(1_300UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        Assert.Equal(1_300UL, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }
}
