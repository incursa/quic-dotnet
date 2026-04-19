namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P2P1-0005")]
public sealed class REQ_QUIC_RFC9000_S14P2P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_IgnoresMalformedQuotedPackets()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] malformedQuotedPacket = [0x80, 0x00];

        Assert.False(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            malformedQuotedPacket,
            1_300));
        Assert.Equal(1_400UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Transition_IgnoresMalformedQuotedPackets()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionIcmpMaximumDatagramSizeReductionEvent(
                ObservedAtTicks: 20,
                runtime.ActivePath!.Value.Identity,
                new byte[] { 0x80, 0x00 },
                1_300),
            nowTicks: 20);

        Assert.False(result.StateChanged);
        Assert.Equal(QuicConnectionEventKind.IcmpMaximumDatagramSizeReduction, result.EventKind);
        Assert.Equal(1_400UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.False(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        Assert.Equal(1_400UL, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }
}
