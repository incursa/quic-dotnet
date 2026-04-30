namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0001">An endpoint MUST initiate a key update by updating its packet protection write secret and using that secret to protect new packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0001")]
public sealed class REQ_QUIC_RFC9001_S6P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeInstallsSuccessorWriteSecretForNewPackets()
    {
        AssertRuntimeInstallsSuccessorWriteSecretForNewPackets(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeInstallsSuccessorWriteSecretForNewPackets()
    {
        AssertRuntimeInstallsSuccessorWriteSecretForNewPackets(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    private static void AssertRuntimeInstallsSuccessorWriteSecretForNewPackets(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial priorProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out _,
            out QuicTlsPacketProtectionMaterial successorProtectMaterial));

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicTlsPacketProtectionMaterial installedProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(successorProtectMaterial.Matches(installedProtectMaterial));
        Assert.False(priorProtectMaterial.Matches(installedProtectMaterial));
        Assert.Equal(1UL, runtime.TlsState.CurrentOneRttKeyPhase);

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            installedProtectMaterial,
            keyPhase: true,
            out byte[] protectedPacket));

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            priorProtectMaterial,
            out _,
            out _,
            out _,
            out _));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            installedProtectMaterial,
            out byte[] openedPacket,
            out _,
            out _,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        Assert.True(parsedHeader.KeyPhase);
    }
}
