namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P5-0007">While repeated 1-RTT key updates remain active, an endpoint MUST keep its internal key-update epoch identifier wide enough to advance beyond the 32-bit boundary without treating the one-bit packet Key Phase signal as the epoch counter.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P5-0007")]
public sealed class REQ_QUIC_RFC9001_S6P5_0007
{
    private const ulong OldThirtyTwoBitBoundaryEpoch = uint.MaxValue;
    private const ulong FirstEpochPastThirtyTwoBitBoundary = OldThirtyTwoBitBoundaryEpoch + 1UL;

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportBridgeInstallsRepeatedLocalUpdateBeyondTheThirtyTwoBitEpochBoundary()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTransportTlsBridgeState state = runtime.TlsState;
        PrepareBridgeAtThirtyTwoBitBoundary(state);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial nextOpenMaterial,
            out QuicTlsPacketProtectionMaterial nextProtectMaterial));
        ulong notBeforeMicros = state.RepeatedLocalOneRttKeyUpdateNotBeforeMicros!.Value;
        Assert.Null(state.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.True(nextOpenMaterial.Matches(state.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(state.CanInitiateRepeatedLocalOneRttKeyUpdate(notBeforeMicros));

        Assert.True(state.TryInstallRepeatedOneRttKeyUpdate(
            nextOpenMaterial,
            nextProtectMaterial,
            notBeforeMicros));

        Assert.Equal(FirstEpochPastThirtyTwoBitBoundary, state.CurrentOneRttKeyPhase);
        Assert.False(state.CurrentOneRttKeyPhaseBit);
        Assert.True(state.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(state.TryArmRetainedOneRttKeyUpdateMaterialDiscard(
            discardAtMicros: 2_000_000,
            keyPhase: OldThirtyTwoBitBoundaryEpoch));
        Assert.Equal(OldThirtyTwoBitBoundaryEpoch, state.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.True(nextOpenMaterial.Matches(state.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(nextProtectMaterial.Matches(state.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportBridgeInstallsRepeatedPeerUpdateBeyondTheThirtyTwoBitEpochBoundary()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTransportTlsBridgeState state = runtime.TlsState;
        PrepareBridgeAtThirtyTwoBitBoundary(state);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial nextOpenMaterial,
            out QuicTlsPacketProtectionMaterial nextProtectMaterial));
        Assert.Null(state.RetainedOldOneRttOpenPacketProtectionMaterial);
        Assert.True(nextOpenMaterial.Matches(state.RetainedNextOneRttOpenPacketProtectionMaterial!.Value));

        Assert.True(state.TryInstallRepeatedPeerOneRttKeyUpdate(
            nextOpenMaterial,
            nextProtectMaterial));

        Assert.Equal(FirstEpochPastThirtyTwoBitBoundary, state.CurrentOneRttKeyPhase);
        Assert.False(state.CurrentOneRttKeyPhaseBit);
        Assert.True(state.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(state.TryArmRetainedOneRttKeyUpdateMaterialDiscard(
            discardAtMicros: 2_000_000,
            keyPhase: OldThirtyTwoBitBoundaryEpoch));
        Assert.Equal(OldThirtyTwoBitBoundaryEpoch, state.RetainedOldOneRttPacketProtectionKeyPhase);
        Assert.True(nextOpenMaterial.Matches(state.OneRttOpenPacketProtectionMaterial!.Value));
        Assert.True(nextProtectMaterial.Matches(state.OneRttProtectPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LifecyclePreservesAcknowledgmentAndRetainedOldStateBeyondTheThirtyTwoBitEpochBoundary()
    {
        QuicOneRttKeyUpdateLifecycle lifecycle = new();
        QuicTlsPacketProtectionMaterial currentOpenMaterial = CreatePacketProtectionMaterial(0x80);
        QuicTlsPacketProtectionMaterial nextOpenMaterial = CreatePacketProtectionMaterial(0x90);
        QuicTlsPacketProtectionMaterial retainedOldOpenMaterial = CreatePacketProtectionMaterial(0xA0);
        QuicTlsPacketProtectionMaterial retainedOldProtectMaterial = CreatePacketProtectionMaterial(0xB0);

        Assert.True(lifecycle.TryRecordCurrentPacketProtectionPhaseAcknowledgment(
            keyPhase: FirstEpochPastThirtyTwoBitBoundary,
            acknowledgedAtMicros: 2_000_000,
            probeTimeoutMicros: 25_000));
        ulong notBeforeMicros = lifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros!.Value;

        Assert.True(lifecycle.TryRetainNextOpenPacketProtectionMaterial(
            currentOpenMaterial,
            nextOpenMaterial));
        Assert.True(lifecycle.TryRetainOldPacketProtectionMaterial(
            retainedOldOpenMaterial,
            retainedOldProtectMaterial));
        Assert.True(lifecycle.TryArmRetainedOldPacketProtectionMaterialDiscard(
            discardAtMicros: 2_500_000,
            keyPhase: OldThirtyTwoBitBoundaryEpoch));

        Assert.Equal(OldThirtyTwoBitBoundaryEpoch, lifecycle.RetainedOldPacketProtectionKeyPhase);
        Assert.True(lifecycle.CurrentPacketProtectionPhaseAcknowledged);
        Assert.True(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(
            FirstEpochPastThirtyTwoBitBoundary,
            notBeforeMicros));
        Assert.False(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(
            OldThirtyTwoBitBoundaryEpoch,
            notBeforeMicros));

        Assert.True(lifecycle.TryDiscardRetainedOldPacketProtectionMaterial());

        Assert.True(lifecycle.CurrentPacketProtectionPhaseAcknowledged);
        Assert.Equal(notBeforeMicros, lifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros);
        Assert.True(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(
            FirstEpochPastThirtyTwoBitBoundary,
            notBeforeMicros));
        Assert.False(lifecycle.HasRetainedOldPacketProtectionMaterial);
        Assert.False(lifecycle.HasRetainedOldPacketProtectionDiscardDeadline);
    }

    private static void PrepareBridgeAtThirtyTwoBitBoundary(QuicTransportTlsBridgeState state)
    {
        Assert.True(state.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(state.OneRttProtectPacketProtectionMaterial.HasValue);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeyUpdateInstalled,
            KeyPhase: uint.MaxValue)));
        Assert.Equal(OldThirtyTwoBitBoundaryEpoch, state.CurrentOneRttKeyPhase);
        Assert.True(state.CurrentOneRttKeyPhaseBit);
        Assert.True(state.TryRecordCurrentOneRttKeyPhaseAcknowledgment(
            acknowledgedAtMicros: 1_000_000,
            probeTimeoutMicros: 25_000));
        Assert.True(state.CurrentOneRttKeyPhaseAcknowledged);
    }

    private static QuicTlsPacketProtectionMaterial CreatePacketProtectionMaterial(byte seed)
    {
        byte[] aeadKey = CreateSequentialBytes(seed, length: 16);
        byte[] aeadIv = CreateSequentialBytes((byte)(seed + 0x10), length: 12);
        byte[] headerProtectionKey = CreateSequentialBytes((byte)(seed + 0x20), length: 16);

        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            QuicRfc9001KeyPhaseTestSupport.CreateSupportedAes128GcmPacketProtectionUsageLimits(),
            out QuicTlsPacketProtectionMaterial material));
        return material;
    }

    private static byte[] CreateSequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(seed + index));
        }

        return bytes;
    }
}
