// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9001-S6-P4-S1-R01">Initiating a key update MUST result in both endpoints updating keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9001-S6-P4-S1-R01")]
public sealed class RFC9001_S6_P4_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeInstallsSuccessorMaterialWhenItInitiatesAKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial priorOpenMaterial = runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial priorProtectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out QuicTlsPacketProtectionMaterial successorProtectMaterial));

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(successorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(successorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.False(priorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.False(priorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeInstallsSuccessorMaterialWhenItInitiatesAKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime();

        QuicTlsPacketProtectionMaterial priorOpenMaterial = runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial priorProtectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out QuicTlsPacketProtectionMaterial successorProtectMaterial));

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(successorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(successorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
        Assert.False(priorOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.False(priorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeRejectsRepeatingTheSameKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicTlsPacketProtectionMaterial installedOpenMaterial = runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial installedProtectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.False(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(installedOpenMaterial.Matches(runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(installedProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }
}
