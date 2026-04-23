namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0008">An endpoint SHOULD retain old keys for some time after it successfully unprotects a packet sent with the new keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0008")]
public sealed class REQ_QUIC_RFC9001_S6P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeRetainsOldOneRttKeysAfterOpeningANewKeyPacket()
    {
        AssertRuntimeRetainsOldOneRttKeysAfterOpeningANewKeyPacket(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeRetainsOldOneRttKeysAfterOpeningANewKeyPacket()
    {
        AssertRuntimeRetainsOldOneRttKeysAfterOpeningANewKeyPacket(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ExplicitRetainedOldKeyCleanupRemovesOldOneRttMaterialAfterTheRetentionWindowOwnerRuns()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);

        Assert.True(runtime.TlsState.TryDiscardRetainedOneRttKeyUpdateMaterial());

        Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
    }

    private static void AssertRuntimeRetainsOldOneRttKeysAfterOpeningANewKeyPacket(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicTlsPacketProtectionMaterial retainedOpenMaterialBeforeOpen =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial installedOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        byte[] protectedPacket =
            QuicRfc9001KeyPhaseTestSupport.CreateSuccessorPhaseOneApplicationPacket(installedOpenMaterial);
        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

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

        QuicTlsPacketProtectionMaterial retainedOpenMaterialAfterOpen =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;

        Assert.True(retainedOpenMaterialAfterOpen.Matches(retainedOpenMaterialBeforeOpen));
        Assert.NotNull(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
    }
}
