// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0015")]
public sealed class REQ_QUIC_RFC9000_S18P2_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DefaultMaxAckDelayPolicyIncludesExpectedAlarmFiringDelay()
    {
        Assert.True(QuicMaxAckDelayPolicy.DefaultExpectedAlarmFiringDelayMicros > 0);
        Assert.Equal(
            QuicMaxAckDelayPolicy.DefaultIntentionalAckDelayMicros
                + QuicMaxAckDelayPolicy.DefaultExpectedAlarmFiringDelayMicros,
            QuicMaxAckDelayPolicy.DefaultMaxAckDelayMicros);
        Assert.Equal(25_000UL, QuicMaxAckDelayPolicy.DefaultMaxAckDelayMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AckDelayTimerUsesDefaultMaxAckDelayIncludingAlarmDelayWhenLocalParameterIsAbsent()
    {
        using QuicConnectionRuntime runtime = QuicS13AckPiggybackTestSupport.CreateAckDelayRuntimeWithValidatedActivePath();

        QuicConnectionTransitionResult result = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 10);

        Assert.Empty(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(
            10 + StopwatchTicksFromMicros(QuicMaxAckDelayPolicy.DefaultMaxAckDelayMicros),
            runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AckDelayTimerUsesComposedMaxAckDelayIncludingExpectedAlarmDelay()
    {
        ulong advertisedMaxAckDelayMicros = QuicMaxAckDelayPolicy.IncludeExpectedAlarmFiringDelay(
            intentionalAckDelayMicros: 11_000,
            expectedAlarmFiringDelayMicros: 1_500);
        using QuicConnectionRuntime runtime =
            QuicS13AckPiggybackTestSupport.CreateAckDelayRuntimeWithValidatedActivePath(
                localMaxAckDelayMicros: advertisedMaxAckDelayMicros);

        QuicConnectionTransitionResult result = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 10);

        Assert.Empty(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(
            10 + StopwatchTicksFromMicros(advertisedMaxAckDelayMicros),
            runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void IncludeExpectedAlarmFiringDelaySaturatesAtTheMaximumInteger()
    {
        Assert.Equal(
            ulong.MaxValue,
            QuicMaxAckDelayPolicy.IncludeExpectedAlarmFiringDelay(ulong.MaxValue - 2, 3));
    }

    private static long StopwatchTicksFromMicros(ulong micros)
    {
        const ulong MicrosecondsPerSecond = 1_000_000UL;

        if (micros == 0)
        {
            return 0;
        }

        ulong frequency = (ulong)System.Diagnostics.Stopwatch.Frequency;
        ulong wholeTicks = micros > ulong.MaxValue / frequency
            ? ulong.MaxValue
            : micros * frequency;
        ulong roundedUp = wholeTicks == ulong.MaxValue
            ? wholeTicks
            : wholeTicks + (MicrosecondsPerSecond - 1);
        ulong ticks = roundedUp / MicrosecondsPerSecond;
        return ticks >= long.MaxValue ? long.MaxValue : (long)ticks;
    }
}
