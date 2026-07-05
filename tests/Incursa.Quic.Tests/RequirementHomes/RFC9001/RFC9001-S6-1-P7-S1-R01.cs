// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="RFC9001-S6-1-P7-S1-R01">The endpoint that initiates a key update MUST also update the keys it uses for receiving packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9001-S6-1-P7-S1-R01")]
public sealed class RFC9001_S6_1_P7_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeInstallsSuccessorReceiveKeysWhenItInitiatesAKeyUpdate()
    {
        AssertRuntimeInstallsSuccessorReceiveKeysWhenItInitiatesAKeyUpdate(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeInstallsSuccessorReceiveKeysWhenItInitiatesAKeyUpdate()
    {
        AssertRuntimeInstallsSuccessorReceiveKeysWhenItInitiatesAKeyUpdate(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    private static void AssertRuntimeInstallsSuccessorReceiveKeysWhenItInitiatesAKeyUpdate(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial priorOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicTlsPacketProtectionMaterial installedOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;

        Assert.True(successorOpenMaterial.Matches(installedOpenMaterial));
        Assert.False(priorOpenMaterial.Matches(installedOpenMaterial));

        byte[] protectedPacket =
            QuicRfc9001KeyPhaseTestSupport.CreateSuccessorPhaseOneApplicationPacket(successorOpenMaterial);
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            priorOpenMaterial,
            out _,
            out _,
            out _,
            out _));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            installedOpenMaterial,
            out byte[] openedPacket,
            out _,
            out _,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        Assert.True(parsedHeader.KeyPhase);
    }
}
