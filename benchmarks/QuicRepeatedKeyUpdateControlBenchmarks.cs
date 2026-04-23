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
    private QuicConnectionSendRuntime repeatedOldSendRuntime = default!;
    private QuicRecoveryController repeatedOldRecoveryController = default!;
    private QuicTlsPacketProtectionMaterial retainedPhaseOneOpenMaterial;
    private QuicTlsPacketProtectionMaterial retainedPhaseOneProtectMaterial;
    private ulong repeatedUpdateNotBeforeMicros;

    [GlobalSetup]
    public void GlobalSetup()
    {
        retainedPhaseOneOpenMaterial = CreatePacketProtectionMaterial(0x30);
        retainedPhaseOneProtectMaterial = CreatePacketProtectionMaterial(0x60);
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
