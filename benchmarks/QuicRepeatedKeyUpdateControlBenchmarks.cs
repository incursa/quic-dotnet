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
    private ulong repeatedUpdateNotBeforeMicros;

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
}
