// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S14-2-1-P4-S3-R01")]
public sealed class RFC9000_S14_2_1_P4_S3_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_AcceptsQuotedPacketsThatMatchTheActivePathAddressAndPort()
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
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_RequiresTheQuotedPacketToMatchTheActivePathAddressAndPort()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);
        QuicConnectionPathIdentity mismatchedPathIdentity = runtime.ActivePath!.Value.Identity with
        {
            RemotePort = 8443,
        };

        Assert.False(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            mismatchedPathIdentity,
            quotedPacket,
            1_300));
        Assert.Equal(1_400UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
    }
}
