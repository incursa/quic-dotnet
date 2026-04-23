namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0004">An endpoint MUST NOT initiate a key update before confirming the handshake.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0004")]
public sealed class REQ_QUIC_RFC9001_S6P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EstablishingClientRuntimeCannotDeriveOrInstallALocalKeyUpdateBeforeHandshakeConfirmation()
    {
        using QuicConnectionRuntime runtime = QuicRfc9001KeyPhaseTestSupport.CreateEstablishingClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.TlsState.OneRttKeysAvailable);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);

        Assert.False(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out _,
            out _));
        Assert.False(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        Assert.False(runtime.TlsState.OneRttKeysAvailable);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0U, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Null(runtime.TlsState.OneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.OneRttProtectPacketProtectionMaterial);
    }
}
