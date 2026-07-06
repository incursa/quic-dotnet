// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S14-2-1-P2-S1-R01")]
public sealed class REQ_QUIC_RFC9000_1421
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Transition_AcceptsAValidatedReductionAtTheRfcMinimumBoundary()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);
        ulong minimumAllowedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionIcmpMaximumDatagramSizeReductionEvent(
                ObservedAtTicks: 20,
                runtime.ActivePath!.Value.Identity,
                quotedPacket,
                minimumAllowedMaximumDatagramSizeBytes),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(minimumAllowedMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        Assert.Equal(minimumAllowedMaximumDatagramSizeBytes, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_IgnoresClaimsBelowTheMinimum()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);
        ulong minimumAllowedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        Assert.False(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            quotedPacket,
            minimumAllowedMaximumDatagramSizeBytes - 1));
        Assert.Equal(1_400UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.False(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        Assert.Equal(1_400UL, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_AcceptsAClaimExactlyAtTheRfcMinimum()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);
        ulong minimumAllowedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        Assert.True(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            quotedPacket,
            minimumAllowedMaximumDatagramSizeBytes));
        Assert.Equal(minimumAllowedMaximumDatagramSizeBytes, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.True(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        Assert.Equal(minimumAllowedMaximumDatagramSizeBytes, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryApplyProvisionalIcmpMaximumDatagramSizeReduction_IgnoresOnlyClaimsBelowTheRfcMinimum()
    {
        ulong minimumAllowedMaximumDatagramSizeBytes =
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;
        ulong[] acceptedSizes =
        [
            minimumAllowedMaximumDatagramSizeBytes,
            minimumAllowedMaximumDatagramSizeBytes + 1,
            minimumAllowedMaximumDatagramSizeBytes + 32,
        ];

        foreach (ulong reducedSize in acceptedSizes)
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
        }

        ulong[] ignoredSizes =
        [
            minimumAllowedMaximumDatagramSizeBytes - 2,
            minimumAllowedMaximumDatagramSizeBytes - 1,
        ];

        foreach (ulong reducedSize in ignoredSizes)
        {
            QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(runtime.ActivePath.HasValue);
            Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

            byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);

            Assert.False(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
                runtime.ActivePath!.Value.Identity,
                quotedPacket,
                reducedSize));
            Assert.Equal(1_400UL, runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
            Assert.False(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        }
    }
}
