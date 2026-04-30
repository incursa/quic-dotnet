namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0003">After initiating a key update, an endpoint MUST toggle the Key Phase bit and protect all subsequent packets with the updated key and IV.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0003")]
public sealed class REQ_QUIC_RFC9001_S6P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitiatedKeyUpdateProtectsConsecutivePacketsWithUpdatedKeyIvAndKeyPhase()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial priorProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.Equal(1UL, runtime.TlsState.CurrentOneRttKeyPhase);

        QuicTlsPacketProtectionMaterial installedProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            installedProtectMaterial,
            keyPhase: true,
            out byte[] firstProtectedPacket));

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            installedProtectMaterial,
            keyPhase: true,
            out byte[] secondProtectedPacket));

        AssertPacketUsesInstalledPhaseOneMaterial(firstProtectedPacket, priorProtectMaterial, installedProtectMaterial);
        AssertPacketUsesInstalledPhaseOneMaterial(secondProtectedPacket, priorProtectMaterial, installedProtectMaterial);
    }

    private static void AssertPacketUsesInstalledPhaseOneMaterial(
        byte[] protectedPacket,
        in QuicTlsPacketProtectionMaterial priorProtectMaterial,
        in QuicTlsPacketProtectionMaterial installedProtectMaterial)
    {
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

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
