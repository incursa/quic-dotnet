// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S14-2-1-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S14P2P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_UsesTheQuotedPacketToMatchTheCurrentConnection()
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
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_IgnoresQuotedPacketsThatBelongToDifferentConnections()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(
            runtime,
            destinationConnectionId: [0x90, 0x91, 0x92]);

        Assert.False(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            quotedPacket,
            1_300));
        Assert.Equal(1_400UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryApplyProvisionalIcmpMaximumDatagramSizeReduction_UsesQuotedPacketConnectionIdsForAssociation()
    {
        (byte[]? DestinationConnectionId, byte[]? SourceConnectionId, bool Expected)[] cases =
        [
            (null, null, true),
            ([0x90, 0x91, 0x92], null, false),
            (null, [0x80, 0x81], false),
            ([0x90], [0x80], false),
        ];

        for (int index = 0; index < cases.Length; index++)
        {
            (byte[]? destinationConnectionId, byte[]? sourceConnectionId, bool expected) = cases[index];
            QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(runtime.ActivePath.HasValue);
            Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

            byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(
                runtime,
                destinationConnectionId,
                sourceConnectionId);
            ulong reducedSize = (ulong)(1_320 - (index * 10));

            Assert.Equal(expected, runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
                runtime.ActivePath!.Value.Identity,
                quotedPacket,
                reducedSize));
            Assert.Equal(
                expected ? reducedSize : 1_400UL,
                runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
            Assert.Equal(expected, runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        }
    }
}
