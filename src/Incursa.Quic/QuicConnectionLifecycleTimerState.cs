using System.Diagnostics;

namespace Incursa.Quic;

/// <summary>
/// Owns lifecycle timer schedules and terminal deadline bookkeeping for a connection.
/// </summary>
internal sealed class QuicConnectionLifecycleTimerState
{
    private const ulong TerminalLifetimePtoMultiplier = 3;
    private const ulong MicrosecondsPerSecond = 1_000_000UL;

    internal QuicConnectionTimerDeadlineState TimerState { get; private set; }

    internal long? TerminalEndTicks { get; private set; }

    internal void UpdateTerminalEndTicks(long nowTicks, ulong currentProbeTimeoutMicros, bool preserveTerminalEndTicks)
    {
        if (!preserveTerminalEndTicks || !TerminalEndTicks.HasValue)
        {
            TerminalEndTicks = ComputeTerminalEndTicks(nowTicks, currentProbeTimeoutMicros);
        }
    }

    internal void ClearTerminalEndTicks()
    {
        TerminalEndTicks = null;
    }

    internal QuicConnectionEffect[] SetTimerDeadline(QuicConnectionTimerKind timerKind, long? dueTicks)
    {
        QuicConnectionTimerSchedule currentSchedule = GetTimerSchedule(timerKind);
        if (currentSchedule.DueTicks == dueTicks)
        {
            return Array.Empty<QuicConnectionEffect>();
        }

        ulong nextGeneration = QuicConnectionTimerDeadlineState.IncrementCounter(currentSchedule.Generation);
        TimerState = TimerState.WithSchedule(timerKind, dueTicks, nextGeneration);

        if (!dueTicks.HasValue)
        {
            return [new QuicConnectionCancelTimerEffect(timerKind, nextGeneration)];
        }

        QuicConnectionTimerPriority priority = TimerState.CreatePriority(dueTicks.Value);
        TimerState = TimerState.AdvancePrioritySequence();
        return [new QuicConnectionArmTimerEffect(timerKind, nextGeneration, priority)];
    }

    internal bool TryConsumeTimerExpiration(QuicConnectionTimerKind timerKind, ulong generation)
    {
        if (!TimerState.IsCurrent(timerKind, generation))
        {
            return false;
        }

        ulong nextGeneration = QuicConnectionTimerDeadlineState.IncrementCounter(TimerState.GetGeneration(timerKind));
        TimerState = TimerState.WithSchedule(timerKind, null, nextGeneration);
        return true;
    }

    private QuicConnectionTimerSchedule GetTimerSchedule(QuicConnectionTimerKind timerKind)
    {
        return timerKind switch
        {
            QuicConnectionTimerKind.IdleTimeout => TimerState.IdleTimeout,
            QuicConnectionTimerKind.CloseLifetime => TimerState.CloseLifetime,
            QuicConnectionTimerKind.DrainLifetime => TimerState.DrainLifetime,
            QuicConnectionTimerKind.PathValidation => TimerState.PathValidation,
            QuicConnectionTimerKind.Recovery => TimerState.Recovery,
            QuicConnectionTimerKind.KeyUpdateRetention => TimerState.KeyUpdateRetention,
            QuicConnectionTimerKind.ApplicationSendDelay => TimerState.ApplicationSendDelay,
            QuicConnectionTimerKind.AckDelay => TimerState.AckDelay,
            _ => throw new ArgumentOutOfRangeException(nameof(timerKind)),
        };
    }

    private long ComputeTerminalEndTicks(long nowTicks, ulong currentProbeTimeoutMicros)
    {
        ulong terminalLifetimeMicros = MultiplySaturating(currentProbeTimeoutMicros, TerminalLifetimePtoMultiplier);
        return SaturatingAdd(nowTicks, ConvertMicrosToTicks(terminalLifetimeMicros));
    }

    private static ulong MultiplySaturating(ulong value, ulong multiplier)
    {
        if (value == 0 || multiplier == 0)
        {
            return 0;
        }

        if (value > ulong.MaxValue / multiplier)
        {
            return ulong.MaxValue;
        }

        return value * multiplier;
    }

    private static long ConvertMicrosToTicks(ulong micros)
    {
        if (micros == 0)
        {
            return 0;
        }

        ulong frequency = (ulong)Stopwatch.Frequency;
        ulong wholeTicks = micros > ulong.MaxValue / frequency
            ? ulong.MaxValue
            : micros * frequency;

        ulong roundedUp = wholeTicks == ulong.MaxValue
            ? wholeTicks
            : wholeTicks + (MicrosecondsPerSecond - 1);

        ulong ticks = roundedUp / MicrosecondsPerSecond;
        return ticks >= long.MaxValue ? long.MaxValue : (long)ticks;
    }

    private static long SaturatingAdd(long left, long right)
    {
        if (right <= 0)
        {
            return left;
        }

        if (left > long.MaxValue - right)
        {
            return long.MaxValue;
        }

        return left + right;
    }
}
