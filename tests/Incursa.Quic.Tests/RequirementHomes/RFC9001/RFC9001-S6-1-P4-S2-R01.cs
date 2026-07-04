// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="RFC9001-S6-1-P4-S2-R01">An endpoint MUST NOT initiate another key update until it has received an acknowledgment for a packet protected with keys from the current key phase.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9001-S6-1-P4-S2-R01")]
public sealed class RFC9001_S6_1_P4_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsASecondLocalUpdateBeforeCurrentPhaseAcknowledgmentSupportExists()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicTlsPacketProtectionMaterial installedOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial installedProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial secondSuccessorOpenMaterial,
            out QuicTlsPacketProtectionMaterial secondSuccessorProtectMaterial));
        Assert.False(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.False(secondSuccessorOpenMaterial.Matches(installedOpenMaterial));
        Assert.False(secondSuccessorProtectMaterial.Matches(installedProtectMaterial));
        Assert.True(installedOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(installedProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }
}
