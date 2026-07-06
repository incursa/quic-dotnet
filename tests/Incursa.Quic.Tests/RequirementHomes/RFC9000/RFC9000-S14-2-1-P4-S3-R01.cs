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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryApplyProvisionalIcmpMaximumDatagramSizeReduction_RequiresMatchingPathAddressAndPort()
    {
        foreach (PathMutation mutation in Enum.GetValues<PathMutation>())
        {
            QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(runtime.ActivePath.HasValue);
            Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

            byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);
            QuicConnectionPathIdentity pathIdentity = MutatePath(runtime.ActivePath!.Value.Identity, mutation);
            bool expected = mutation == PathMutation.None;

            Assert.Equal(expected, runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
                pathIdentity,
                quotedPacket,
                1_300));
            Assert.Equal(
                expected ? 1_300UL : 1_400UL,
                runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
            Assert.Equal(expected, runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        }
    }

    private static QuicConnectionPathIdentity MutatePath(
        QuicConnectionPathIdentity pathIdentity,
        PathMutation mutation)
    {
        return mutation switch
        {
            PathMutation.None => pathIdentity,
            PathMutation.RemoteAddress => pathIdentity with { RemoteAddress = "198.51.100.77" },
            PathMutation.LocalAddress => pathIdentity with { LocalAddress = "198.51.100.78" },
            PathMutation.RemotePort => pathIdentity with { RemotePort = pathIdentity.RemotePort.GetValueOrDefault() + 1 },
            PathMutation.LocalPort => pathIdentity with { LocalPort = pathIdentity.LocalPort.GetValueOrDefault() + 1 },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation), mutation, null),
        };
    }

    private enum PathMutation
    {
        None,
        RemoteAddress,
        LocalAddress,
        RemotePort,
        LocalPort,
    }
}
