namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P2-0003")]
public sealed class REQ_QUIC_RFC9000_S10P2_0003
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
