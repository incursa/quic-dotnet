// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S10-2-P6-S3-R01")]
public sealed class REQ_QUIC_RFC9000_0569
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerTerminalLifetimeExpiryDiscardsConnectionState(bool useLocalCloseRequest)
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        ApplyTerminalTransition(runtime, useLocalCloseRequest, nowTicks: 1);

        QuicConnectionTimerKind timerKind = useLocalCloseRequest
            ? QuicConnectionTimerKind.CloseLifetime
            : QuicConnectionTimerKind.DrainLifetime;

        long dueTicks = runtime.TimerState.GetDueTicks(timerKind)!.Value;
        ulong generation = runtime.TimerState.GetGeneration(timerKind);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks,
                timerKind,
                generation),
            nowTicks: dueTicks);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerEnteringClosingOrDrainingStateDoesNotDiscardImmediately(bool useLocalCloseRequest)
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult result = ApplyTerminalTransition(runtime, useLocalCloseRequest, nowTicks: 1);

        QuicConnectionTimerKind timerKind = useLocalCloseRequest
            ? QuicConnectionTimerKind.CloseLifetime
            : QuicConnectionTimerKind.DrainLifetime;

        Assert.Equal(
            useLocalCloseRequest ? QuicConnectionPhase.Closing : QuicConnectionPhase.Draining,
            runtime.Phase);
        Assert.True(runtime.TimerState.GetDueTicks(timerKind).HasValue);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [Requirement("RFC9000-S10-2-P6-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerTerminalStatesPersistUntilTheirLifetimeExpires()
    {
        long[] observedTicks = [1, 9, 37, 101];
        bool[] terminalTransitions = [true, false];

        foreach (long nowTicks in observedTicks)
        {
            foreach (bool useLocalCloseRequest in terminalTransitions)
            {
                QuicConnectionRuntime runtime = CreateRuntime();

                QuicConnectionTransitionResult terminalResult =
                    ApplyTerminalTransition(runtime, useLocalCloseRequest, nowTicks);

                QuicConnectionTimerKind timerKind = useLocalCloseRequest
                    ? QuicConnectionTimerKind.CloseLifetime
                    : QuicConnectionTimerKind.DrainLifetime;

                Assert.Equal(
                    useLocalCloseRequest ? QuicConnectionPhase.Closing : QuicConnectionPhase.Draining,
                    runtime.Phase);
                Assert.DoesNotContain(terminalResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);

                long dueTicks = runtime.TimerState.GetDueTicks(timerKind)!.Value;
                ulong generation = runtime.TimerState.GetGeneration(timerKind);

                QuicConnectionTransitionResult expiryResult = runtime.Transition(
                    new QuicConnectionTimerExpiredEvent(
                        ObservedAtTicks: dueTicks,
                        timerKind,
                        generation),
                    nowTicks: dueTicks);

                Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
                Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
                Assert.Contains(expiryResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
            }
        }
    }

    private static QuicConnectionTransitionResult ApplyTerminalTransition(
        QuicConnectionRuntime runtime,
        bool useLocalCloseRequest,
        long nowTicks)
    {
        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: useLocalCloseRequest ? "closing" : "draining");

        return useLocalCloseRequest
            ? runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: nowTicks,
                    closeMetadata),
                nowTicks)
            : runtime.Transition(
                new QuicConnectionConnectionCloseFrameReceivedEvent(
                    ObservedAtTicks: nowTicks,
                    closeMetadata),
                nowTicks);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return QuicS17P2P2TestSupport.CreateServerRuntime();
    }
}
