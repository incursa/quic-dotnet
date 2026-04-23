namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0006">The endpoint that initiates a key update MUST also update the keys it uses for receiving packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0006")]
public sealed class REQ_QUIC_RFC9001_S6P1_0006
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
