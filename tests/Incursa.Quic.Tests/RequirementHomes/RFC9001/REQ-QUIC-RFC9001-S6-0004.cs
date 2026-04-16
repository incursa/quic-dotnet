namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0004">The Key Phase bit MUST be toggled to signal each subsequent key update.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6-0004")]
public sealed class REQ_QUIC_RFC9001_S6_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeTogglesOutboundKeyPhaseAfterInstallingSuccessorMaterial()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);

        QuicTlsPacketProtectionMaterial priorProtectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            CreatePingPayload(),
            priorProtectMaterial,
            keyPhase: false,
            out byte[] phaseZeroPacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            phaseZeroPacket,
            priorProtectMaterial,
            out byte[] openedPhaseZeroPacket,
            out _,
            out _,
            out bool observedPhaseZeroKeyPhase));

        Assert.False(observedPhaseZeroKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPhaseZeroPacket, out QuicShortHeaderPacket parsedPhaseZeroHeader));
        Assert.False(parsedPhaseZeroHeader.KeyPhase);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.False(priorProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));

        QuicTlsPacketProtectionMaterial installedProtectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            CreatePingPayload(),
            installedProtectMaterial,
            keyPhase: runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] phaseOnePacket));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            phaseOnePacket,
            installedProtectMaterial,
            out byte[] openedPhaseOnePacket,
            out _,
            out _,
            out bool observedPhaseOneKeyPhase));

        Assert.True(observedPhaseOneKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPhaseOnePacket, out QuicShortHeaderPacket parsedPhaseOneHeader));
        Assert.True(parsedPhaseOneHeader.KeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeRejectsRepeatingTheSameOneRttKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        QuicTlsPacketProtectionMaterial installedProtectMaterial = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.False(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.True(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.True(installedProtectMaterial.Matches(runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value));
    }

    private static byte[] CreatePingPayload()
    {
        byte[] payload = new byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }
}
