// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S14-2-1-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_1422
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_ValidatesQuotedPacketBeforeReducingTheActivePath()
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
        Assert.Equal(1_300UL, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_RejectsMismatchedQuotedPackets()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(
            runtime,
            destinationConnectionId: [0x99]);

        Assert.False(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            quotedPacket,
            1_300));
        Assert.Equal(1_400UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.Equal(1_400UL, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }
}
