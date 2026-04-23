namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0007">An endpoint MUST retain old keys until it has successfully unprotected a packet sent with the new keys.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0007")]
public sealed class REQ_QUIC_RFC9001_S6P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeRetainsOldOneRttKeysWhenAKeyUpdateIsInstalled()
    {
        AssertRuntimeRetainsOldOneRttKeysWhenAKeyUpdateIsInstalled(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveServerRuntimeRetainsOldOneRttKeysWhenAKeyUpdateIsInstalled()
    {
        AssertRuntimeRetainsOldOneRttKeysWhenAKeyUpdateIsInstalled(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EstablishingClientRuntimeDoesNotInventRetainedOldKeysBeforeAKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicRfc9001KeyPhaseTestSupport.CreateEstablishingClientRuntime();

        Assert.Null(runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial);
        Assert.False(runtime.TlsState.TryDiscardRetainedOneRttKeyUpdateMaterial());
    }

    private static void AssertRuntimeRetainsOldOneRttKeysWhenAKeyUpdateIsInstalled(
        Func<QuicConnectionRuntime> runtimeFactory)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        QuicTlsPacketProtectionMaterial priorOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial priorProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        QuicTlsPacketProtectionMaterial retainedOpenMaterial =
            runtime.TlsState.RetainedOldOneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial retainedProtectMaterial =
            runtime.TlsState.RetainedOldOneRttProtectPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial currentProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(retainedOpenMaterial.Matches(priorOpenMaterial));
        Assert.True(retainedProtectMaterial.Matches(priorProtectMaterial));
        Assert.False(retainedOpenMaterial.Matches(currentOpenMaterial));
        Assert.False(retainedProtectMaterial.Matches(currentProtectMaterial));
        Assert.Equal(1U, runtime.TlsState.CurrentOneRttKeyPhase);
    }
}
