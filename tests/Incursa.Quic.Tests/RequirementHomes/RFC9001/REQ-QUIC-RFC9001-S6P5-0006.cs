namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P5-0006">While repeated 1-RTT key updates remain active, an endpoint MUST keep current, next, and retained-old 1-RTT epoch ownership distinct, MUST use the active epoch's packet-number floor to select retained, current, or next packet-protection material, and MUST synchronize retained-old discard with matching sender and recovery cleanup without clearing current-phase acknowledgment or repeated-update cooldown state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P5-0006")]
public sealed class REQ_QUIC_RFC9001_S6P5_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LifecycleKeepsCurrentNextAndRetainedOldOwnershipDistinctDuringRepeatedCleanup()
    {
        QuicOneRttKeyUpdateLifecycle lifecycle = new();
        QuicTlsPacketProtectionMaterial currentOpenMaterial = CreatePacketProtectionMaterial(0x10);
        QuicTlsPacketProtectionMaterial nextOpenMaterial = CreatePacketProtectionMaterial(0x20);
        QuicTlsPacketProtectionMaterial retainedOldOpenMaterial = CreatePacketProtectionMaterial(0x30);
        QuicTlsPacketProtectionMaterial retainedOldProtectMaterial = CreatePacketProtectionMaterial(0x40);

        Assert.True(lifecycle.TryRecordCurrentPacketProtectionPhaseAcknowledgment(
            keyPhase: 17,
            acknowledgedAtMicros: 1_000_000,
            probeTimeoutMicros: 25_000));
        ulong notBeforeMicros = lifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros!.Value;

        Assert.True(lifecycle.TryRetainNextOpenPacketProtectionMaterial(
            currentOpenMaterial,
            nextOpenMaterial));
        Assert.True(lifecycle.TryRetainOldPacketProtectionMaterial(
            retainedOldOpenMaterial,
            retainedOldProtectMaterial));
        Assert.True(lifecycle.TryArmRetainedOldPacketProtectionMaterialDiscard(
            discardAtMicros: 1_500_000,
            keyPhase: 16));

        Assert.True(lifecycle.HasRetainedNextOpenPacketProtectionMaterial);
        Assert.True(lifecycle.HasRetainedOldPacketProtectionMaterial);
        Assert.Equal(16UL, lifecycle.RetainedOldPacketProtectionKeyPhase);
        Assert.True(lifecycle.CurrentPacketProtectionPhaseAcknowledged);
        Assert.Equal(notBeforeMicros, lifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros);

        Assert.True(lifecycle.TryDiscardRetainedOldPacketProtectionMaterial());

        Assert.True(lifecycle.HasRetainedNextOpenPacketProtectionMaterial);
        Assert.False(lifecycle.HasRetainedOldPacketProtectionMaterial);
        Assert.False(lifecycle.HasRetainedOldPacketProtectionDiscardDeadline);
        Assert.True(lifecycle.CurrentPacketProtectionPhaseAcknowledged);
        Assert.Equal(notBeforeMicros, lifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros);
        Assert.True(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(17, notBeforeMicros));
        Assert.True(nextOpenMaterial.Matches(lifecycle.RetainedNextOpenPacketProtectionMaterial!.Value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LifecycleRejectsReplacingExistingNextAndRetainedOldOwnership()
    {
        QuicOneRttKeyUpdateLifecycle lifecycle = new();
        QuicTlsPacketProtectionMaterial currentOpenMaterial = CreatePacketProtectionMaterial(0x11);
        QuicTlsPacketProtectionMaterial nextOpenMaterial = CreatePacketProtectionMaterial(0x21);
        QuicTlsPacketProtectionMaterial replacementNextOpenMaterial = CreatePacketProtectionMaterial(0x22);
        QuicTlsPacketProtectionMaterial retainedOldOpenMaterial = CreatePacketProtectionMaterial(0x31);
        QuicTlsPacketProtectionMaterial retainedOldProtectMaterial = CreatePacketProtectionMaterial(0x41);
        QuicTlsPacketProtectionMaterial replacementRetainedOldOpenMaterial = CreatePacketProtectionMaterial(0x32);
        QuicTlsPacketProtectionMaterial replacementRetainedOldProtectMaterial = CreatePacketProtectionMaterial(0x42);

        Assert.True(lifecycle.TryRecordCurrentPacketProtectionPhaseAcknowledgment(
            keyPhase: 9,
            acknowledgedAtMicros: 2_000_000,
            probeTimeoutMicros: 25_000));
        ulong notBeforeMicros = lifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros!.Value;

        Assert.True(lifecycle.TryRetainNextOpenPacketProtectionMaterial(
            currentOpenMaterial,
            nextOpenMaterial));
        Assert.True(lifecycle.TryRetainOldPacketProtectionMaterial(
            retainedOldOpenMaterial,
            retainedOldProtectMaterial));

        Assert.False(lifecycle.TryRetainNextOpenPacketProtectionMaterial(
            currentOpenMaterial,
            replacementNextOpenMaterial));
        Assert.False(lifecycle.TryRetainOldPacketProtectionMaterial(
            replacementRetainedOldOpenMaterial,
            replacementRetainedOldProtectMaterial));

        Assert.True(nextOpenMaterial.Matches(lifecycle.RetainedNextOpenPacketProtectionMaterial!.Value));
        Assert.True(retainedOldOpenMaterial.Matches(lifecycle.RetainedOldOpenPacketProtectionMaterial!.Value));
        Assert.True(retainedOldProtectMaterial.Matches(lifecycle.RetainedOldProtectPacketProtectionMaterial!.Value));
        Assert.True(lifecycle.CurrentPacketProtectionPhaseAcknowledged);
        Assert.Equal(notBeforeMicros, lifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros);
        Assert.True(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(9, notBeforeMicros));
        Assert.False(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(10, notBeforeMicros));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzLifecycleOwnershipDistinctnessAcrossSampledRepeatedEpochPhases()
    {
        Random random = new(unchecked((int)0x9001_6506));

        for (int iteration = 0; iteration < 32; iteration++)
        {
            QuicOneRttKeyUpdateLifecycle lifecycle = new();
            ulong keyPhase = (ulong)random.Next(1, 1_024);
            ulong acknowledgedAtMicros = (ulong)random.Next(1_000, 100_000);
            ulong probeTimeoutMicros = (ulong)random.Next(1, 25_000);
            ulong currentNotBeforeMicros = acknowledgedAtMicros + (probeTimeoutMicros * 3UL);

            QuicTlsPacketProtectionMaterial currentOpenMaterial = CreatePacketProtectionMaterial((byte)(0x50 + iteration));
            QuicTlsPacketProtectionMaterial nextOpenMaterial = CreatePacketProtectionMaterial((byte)(0x70 + iteration));
            QuicTlsPacketProtectionMaterial retainedOldOpenMaterial = CreatePacketProtectionMaterial((byte)(0x90 + iteration));
            QuicTlsPacketProtectionMaterial retainedOldProtectMaterial = CreatePacketProtectionMaterial((byte)(0xB0 + iteration));

            Assert.True(lifecycle.TryRecordCurrentPacketProtectionPhaseAcknowledgment(
                keyPhase,
                acknowledgedAtMicros,
                probeTimeoutMicros));
            Assert.True(lifecycle.TryRetainNextOpenPacketProtectionMaterial(
                currentOpenMaterial,
                nextOpenMaterial));
            Assert.True(lifecycle.TryRetainOldPacketProtectionMaterial(
                retainedOldOpenMaterial,
                retainedOldProtectMaterial));
            Assert.True(lifecycle.TryArmRetainedOldPacketProtectionMaterialDiscard(
                currentNotBeforeMicros,
                keyPhase - 1UL));

            Assert.False(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(keyPhase, currentNotBeforeMicros - 1));
            Assert.True(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(keyPhase, currentNotBeforeMicros));
            Assert.False(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(keyPhase + 1UL, currentNotBeforeMicros));

            Assert.True(lifecycle.TryDiscardRetainedOldPacketProtectionMaterial());
            Assert.True(lifecycle.CurrentPacketProtectionPhaseAcknowledged);
            Assert.Equal(currentNotBeforeMicros, lifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros);
            Assert.True(nextOpenMaterial.Matches(lifecycle.RetainedNextOpenPacketProtectionMaterial!.Value));
            Assert.False(lifecycle.HasRetainedOldPacketProtectionMaterial);
            Assert.False(lifecycle.HasRetainedOldPacketProtectionDiscardDeadline);
            Assert.True(lifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(keyPhase, currentNotBeforeMicros));
        }
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
            new QuicAeadUsageLimits(64, 128),
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
