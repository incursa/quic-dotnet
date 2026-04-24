using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the repeated local key-update control plane that records current-phase acknowledgment
/// and checks the three-PTO cooldown before another locally initiated update may proceed.
/// </summary>
[MemoryDiagnoser]
public class QuicRepeatedKeyUpdateControlBenchmarks
{
    private const uint CurrentKeyPhase = 1;
    private const ulong AcknowledgedAtMicros = 1_000_000;
    private const ulong ProbeTimeoutMicros = 25_000;

    private QuicOneRttKeyUpdateLifecycle pendingConfirmationLifecycle = default!;
    private QuicOneRttKeyUpdateLifecycle confirmedLifecycle = default!;
    private QuicOneRttKeyUpdateLifecycle retainedPhaseOneLifecycle = default!;
    private QuicOneRttKeyUpdateLifecycle retainedPhaseTwoLifecycle = default!;
    private QuicAeadKeyLifecycle exhaustedRepeatedProtectionLifecycle = default!;
    private QuicConnectionSendRuntime repeatedOldSendRuntime = default!;
    private QuicRecoveryController repeatedOldRecoveryController = default!;
    private QuicConnectionSendRuntime repeatedPhaseTwoOldSendRuntime = default!;
    private QuicRecoveryController repeatedPhaseTwoOldRecoveryController = default!;
    private QuicTlsPacketProtectionMaterial retainedPhaseOneOpenMaterial;
    private QuicTlsPacketProtectionMaterial retainedPhaseOneProtectMaterial;
    private QuicTlsPacketProtectionMaterial retainedPhaseTwoOpenMaterial;
    private QuicTlsPacketProtectionMaterial retainedPhaseTwoProtectMaterial;
    private ulong repeatedUpdateNotBeforeMicros;

    [GlobalSetup]
    public void GlobalSetup()
    {
        retainedPhaseOneOpenMaterial = CreatePacketProtectionMaterial(0x30);
        retainedPhaseOneProtectMaterial = CreatePacketProtectionMaterial(0x60);
        retainedPhaseTwoOpenMaterial = CreatePacketProtectionMaterial(0x90);
        retainedPhaseTwoProtectMaterial = CreatePacketProtectionMaterial(0xC0);
    }

    [IterationSetup]
    public void IterationSetup()
    {
        pendingConfirmationLifecycle = new QuicOneRttKeyUpdateLifecycle();
        confirmedLifecycle = new QuicOneRttKeyUpdateLifecycle();
        if (!confirmedLifecycle.TryRecordCurrentPacketProtectionPhaseAcknowledgment(
                CurrentKeyPhase,
                AcknowledgedAtMicros,
                ProbeTimeoutMicros))
        {
            throw new InvalidOperationException("Failed to prepare the repeated local key-update cooldown state.");
        }

        repeatedUpdateNotBeforeMicros = confirmedLifecycle.RepeatedLocalPacketProtectionUpdateNotBeforeMicros
            ?? throw new InvalidOperationException("The repeated local key-update cooldown deadline was not recorded.");

        exhaustedRepeatedProtectionLifecycle = new QuicAeadKeyLifecycle(new QuicAeadUsageLimits(1, 128));
        if (!exhaustedRepeatedProtectionLifecycle.TryActivate()
            || !exhaustedRepeatedProtectionLifecycle.TryUseForProtection())
        {
            throw new InvalidOperationException("Failed to prepare the repeated AEAD-limit protection state.");
        }

        retainedPhaseOneLifecycle = new QuicOneRttKeyUpdateLifecycle();
        if (!retainedPhaseOneLifecycle.TryRetainOldPacketProtectionMaterial(
                retainedPhaseOneOpenMaterial,
                retainedPhaseOneProtectMaterial)
            || !retainedPhaseOneLifecycle.TryArmRetainedOldPacketProtectionMaterialDiscard(
                AcknowledgedAtMicros + (ProbeTimeoutMicros * 3UL),
                keyPhase: 1))
        {
            throw new InvalidOperationException("Failed to prepare the repeated old-key discard lifecycle state.");
        }

        repeatedOldSendRuntime = new QuicConnectionSendRuntime();
        repeatedOldRecoveryController = new QuicRecoveryController();
        SeedOneRttPacket(repeatedOldSendRuntime, repeatedOldRecoveryController, packetNumber: 30, keyPhase: 1);
        SeedOneRttPacket(repeatedOldSendRuntime, repeatedOldRecoveryController, packetNumber: 31, keyPhase: 2);
        SeedOneRttPacket(repeatedOldSendRuntime, repeatedOldRecoveryController, packetNumber: 32, keyPhase: 1);
        if (!repeatedOldSendRuntime.TryRegisterLoss(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber: 32,
                handshakeConfirmed: true))
        {
            throw new InvalidOperationException("Failed to prepare repeated old-key pending retransmission state.");
        }

        retainedPhaseTwoLifecycle = new QuicOneRttKeyUpdateLifecycle();
        if (!retainedPhaseTwoLifecycle.TryRetainOldPacketProtectionMaterial(
                retainedPhaseTwoOpenMaterial,
                retainedPhaseTwoProtectMaterial)
            || !retainedPhaseTwoLifecycle.TryArmRetainedOldPacketProtectionMaterialDiscard(
                AcknowledgedAtMicros + (ProbeTimeoutMicros * 3UL),
                keyPhase: 2))
        {
            throw new InvalidOperationException("Failed to prepare repeated phase-2 old-key discard lifecycle state.");
        }

        repeatedPhaseTwoOldSendRuntime = new QuicConnectionSendRuntime();
        repeatedPhaseTwoOldRecoveryController = new QuicRecoveryController();
        SeedOneRttPacket(repeatedPhaseTwoOldSendRuntime, repeatedPhaseTwoOldRecoveryController, packetNumber: 50, keyPhase: 2);
        SeedOneRttPacket(repeatedPhaseTwoOldSendRuntime, repeatedPhaseTwoOldRecoveryController, packetNumber: 51, keyPhase: 3);
        SeedOneRttPacket(repeatedPhaseTwoOldSendRuntime, repeatedPhaseTwoOldRecoveryController, packetNumber: 52, keyPhase: 2);
        if (!repeatedPhaseTwoOldSendRuntime.TryRegisterLoss(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber: 52,
                handshakeConfirmed: true))
        {
            throw new InvalidOperationException("Failed to prepare repeated phase-2 pending retransmission state.");
        }
    }

    /// <summary>
    /// Measures recording the acknowledgment that confirms the current key phase and arming the
    /// corresponding three-PTO local key-update cooldown.
    /// </summary>
    [Benchmark]
    public int RecordCurrentKeyPhaseAcknowledgmentAndArmCooldown()
    {
        pendingConfirmationLifecycle.ResetRepeatedLocalPacketProtectionUpdateEligibility();
        return pendingConfirmationLifecycle.TryRecordCurrentPacketProtectionPhaseAcknowledgment(
            CurrentKeyPhase,
            AcknowledgedAtMicros,
            ProbeTimeoutMicros)
            ? 1
            : -1;
    }

    /// <summary>
    /// Measures checking whether the repeated local key-update cooldown has expired for the current key phase.
    /// </summary>
    [Benchmark]
    public int CheckRepeatedLocalKeyUpdateEligibilityAfterCooldown()
    {
        return confirmedLifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(
            CurrentKeyPhase,
            repeatedUpdateNotBeforeMicros)
            ? 1
            : -1;
    }

    /// <summary>
    /// Measures the AEAD-limit decision that requests a repeated local update after the cooldown gate opens.
    /// </summary>
    [Benchmark]
    public int EvaluateRepeatedAeadLimitUpdateDecisionAfterCooldown()
    {
        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            exhaustedRepeatedProtectionLifecycle,
            confirmedLifecycle.CanInitiateRepeatedLocalPacketProtectionUpdate(
                CurrentKeyPhase,
                repeatedUpdateNotBeforeMicros));

        return decision.Action == QuicAeadLimitAction.InitiateKeyUpdate ? 1 : -1;
    }

    /// <summary>
    /// Measures the repeated old-key cleanup boundary for retained phase-1 material plus sender/recovery state.
    /// </summary>
    [Benchmark]
    public int DiscardRepeatedOldPhaseOnePacketProtectionAndSendState()
    {
        bool updated = retainedPhaseOneLifecycle.TryDiscardRetainedOldPacketProtectionMaterial();
        updated |= repeatedOldSendRuntime.TryDiscardOneRttKeyPhase(1);
        updated |= repeatedOldRecoveryController.TryDiscardOneRttKeyPhase(1);

        return updated ? repeatedOldSendRuntime.SentPackets.Count + repeatedOldSendRuntime.PendingRetransmissionCount : -1;
    }

    /// <summary>
    /// Measures the same repeated old-key cleanup after one more bounded alternation, where phase 2 is retained old
    /// and phase 3 remains current.
    /// </summary>
    [Benchmark]
    public int DiscardRepeatedOldPhaseTwoPacketProtectionAndSendState()
    {
        bool updated = retainedPhaseTwoLifecycle.TryDiscardRetainedOldPacketProtectionMaterial();
        updated |= repeatedPhaseTwoOldSendRuntime.TryDiscardOneRttKeyPhase(2);
        updated |= repeatedPhaseTwoOldRecoveryController.TryDiscardOneRttKeyPhase(2);

        return updated
            ? repeatedPhaseTwoOldSendRuntime.SentPackets.Count + repeatedPhaseTwoOldSendRuntime.PendingRetransmissionCount
            : -1;
    }

    private static QuicTlsPacketProtectionMaterial CreatePacketProtectionMaterial(byte seed)
    {
        byte[] aeadKey = CreateSequentialBytes(seed, length: 16);
        byte[] aeadIv = CreateSequentialBytes((byte)(seed + 0x10), length: 12);
        byte[] headerProtectionKey = CreateSequentialBytes((byte)(seed + 0x20), length: 16);
        if (!QuicTlsPacketProtectionMaterial.TryCreate(
                QuicTlsEncryptionLevel.OneRtt,
                QuicAeadAlgorithm.Aes128Gcm,
                aeadKey,
                aeadIv,
                headerProtectionKey,
                new QuicAeadUsageLimits(64, 128),
                out QuicTlsPacketProtectionMaterial material))
        {
            throw new InvalidOperationException("Failed to prepare benchmark packet-protection material.");
        }

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

    private static void SeedOneRttPacket(
        QuicConnectionSendRuntime sendRuntime,
        QuicRecoveryController recoveryController,
        ulong packetNumber,
        uint keyPhase)
    {
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            PayloadBytes: 1_200,
            SentAtMicros: packetNumber * 10,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: new byte[] { (byte)(packetNumber & 0xFF) },
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            OneRttKeyPhase: keyPhase));
        recoveryController.RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            sentAtMicros: packetNumber * 10,
            isAckElicitingPacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            oneRttKeyPhase: keyPhase);
    }
}
