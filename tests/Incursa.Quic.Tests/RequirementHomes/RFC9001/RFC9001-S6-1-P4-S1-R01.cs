// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="RFC9001-S6-1-P4-S1-R01">An endpoint MUST NOT initiate a key update before confirming the handshake.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9001-S6-1-P4-S1-R01")]
public sealed class RFC9001_S6_1_P4_S1_R01
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
        Assert.Equal(0UL, runtime.TlsState.CurrentOneRttKeyPhase);

        Assert.False(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out _,
            out _));
        Assert.False(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));

        Assert.False(runtime.TlsState.OneRttKeysAvailable);
        Assert.False(runtime.TlsState.KeyUpdateInstalled);
        Assert.Equal(0UL, runtime.TlsState.CurrentOneRttKeyPhase);
        Assert.Null(runtime.TlsState.OneRttOpenPacketProtectionMaterial);
        Assert.Null(runtime.TlsState.OneRttProtectPacketProtectionMaterial);
    }
}
