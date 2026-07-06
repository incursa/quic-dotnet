// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S14-2-1-P5-S2-R01")]
public sealed class REQ_QUIC_RFC9000_1428
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_DoesNotMarkThePathProvisionalWhenValidationFails()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        Assert.False(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            new byte[] { 0x80, 0x00 },
            1_300));
        Assert.False(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        Assert.Equal(1_400UL, runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
    }

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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryApplyProvisionalIcmpMaximumDatagramSizeReduction_MarksAcceptedReductionsAsProvisional()
    {
        ulong[] reducedSizes =
        [
            1_399,
            1_350,
            1_300,
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes,
        ];

        foreach (ulong reducedSize in reducedSizes)
        {
            QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(runtime.ActivePath.HasValue);
            Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

            byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);

            Assert.True(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
                runtime.ActivePath!.Value.Identity,
                quotedPacket,
                reducedSize));
            Assert.Equal(reducedSize, runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
            Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
            Assert.Equal(reducedSize, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
        }
    }
}
