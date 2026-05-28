// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionLifecycleTimerStateTests
{
    [Fact]
    public void SetTimerDeadline_RearmsCancelsAndAdvancesTheGenerationCounter()
    {
        QuicConnectionLifecycleTimerState timerState = new();

        QuicConnectionArmTimerEffect firstArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(timerState.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 10)));

        QuicConnectionArmTimerEffect secondArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(timerState.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 20)));

        QuicConnectionCancelTimerEffect cancelEffect = Assert.IsType<QuicConnectionCancelTimerEffect>(
            Assert.Single(timerState.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, null)));

        Assert.Equal(1UL, firstArm.Generation);
        Assert.Equal(2UL, secondArm.Generation);
        Assert.Equal(3UL, cancelEffect.Generation);
        Assert.Null(timerState.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.Equal(cancelEffect.Generation, timerState.TimerState.GetGeneration(QuicConnectionTimerKind.IdleTimeout));
    }

    [Fact]
    public void TryConsumeTimerExpiration_RejectsStaleGenerationsAndClearsCurrentDeadline()
    {
        QuicConnectionLifecycleTimerState timerState = new();

        QuicConnectionArmTimerEffect originalArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(timerState.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 10)));

        QuicConnectionArmTimerEffect currentArm = Assert.IsType<QuicConnectionArmTimerEffect>(
            Assert.Single(timerState.SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, 20)));

        Assert.False(timerState.TryConsumeTimerExpiration(QuicConnectionTimerKind.IdleTimeout, originalArm.Generation));
        Assert.Equal(20L, timerState.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.True(timerState.TryConsumeTimerExpiration(QuicConnectionTimerKind.IdleTimeout, currentArm.Generation));
        Assert.Null(timerState.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));
        Assert.Equal(QuicConnectionTimerDeadlineState.IncrementCounter(currentArm.Generation), timerState.TimerState.GetGeneration(QuicConnectionTimerKind.IdleTimeout));
    }

    [Fact]
    public void UpdateTerminalEndTicks_ComputesAndPreservesTheStoredDeadline()
    {
        QuicConnectionLifecycleTimerState timerState = new();
        long nowTicks = 1_000;
        ulong currentProbeTimeoutMicros = 200;
        long expectedDeadline = ComputeExpectedTerminalDeadline(nowTicks, currentProbeTimeoutMicros);

        timerState.UpdateTerminalEndTicks(nowTicks, currentProbeTimeoutMicros, preserveTerminalEndTicks: false);

        Assert.Equal(expectedDeadline, timerState.TerminalEndTicks);

        timerState.UpdateTerminalEndTicks(nowTicks + 50, currentProbeTimeoutMicros + 100, preserveTerminalEndTicks: true);

        Assert.Equal(expectedDeadline, timerState.TerminalEndTicks);

        timerState.ClearTerminalEndTicks();
        timerState.UpdateTerminalEndTicks(nowTicks + 75, currentProbeTimeoutMicros, preserveTerminalEndTicks: true);

        Assert.Equal(ComputeExpectedTerminalDeadline(nowTicks + 75, currentProbeTimeoutMicros), timerState.TerminalEndTicks);
    }

    private static long ComputeExpectedTerminalDeadline(long nowTicks, ulong currentProbeTimeoutMicros)
    {
        ulong terminalLifetimeMicros = MultiplySaturating(currentProbeTimeoutMicros, 3);
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
            : wholeTicks + 999_999UL;

        ulong ticks = roundedUp / 1_000_000UL;
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
