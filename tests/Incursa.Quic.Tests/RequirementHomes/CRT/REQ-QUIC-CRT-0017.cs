namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0017")]
public sealed class REQ_QUIC_CRT_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RunAsyncProcessesInboxEventsInPostedOrder()
    {
        FakeMonotonicClock clock = new(123_456_789);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        List<QuicConnectionEventKind> observedKinds = [];
        TaskCompletionSource<bool> observedThreeEvents = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = runtime.RunAsync(
            transition =>
            {
                observedKinds.Add(transition.EventKind);

                if (observedKinds.Count == 3)
                {
                    observedThreeEvents.TrySetResult(true);
                }
            },
            cancellationToken: cancellation.Token);

        Assert.True(runtime.TryPostNetworkEvent(new QuicConnectionPacketReceivedEvent(
            ObservedAtTicks: 1,
            new QuicConnectionPathIdentity("203.0.113.1"),
            ReadOnlyMemory<byte>.Empty)));

        Assert.True(runtime.TryPostLocalApiEvent(new QuicConnectionHandshakeConfirmedEvent(ObservedAtTicks: 2)));

        Assert.True(runtime.TryPostTimerEvent(new QuicConnectionTimerExpiredEvent(
            ObservedAtTicks: 3,
            QuicConnectionTimerKind.IdleTimeout,
            Generation: 0)));

        await observedThreeEvents.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();
        await consumer;
        await runtime.DisposeAsync();

        Assert.Equal(
            [
                QuicConnectionEventKind.PacketReceived,
                QuicConnectionEventKind.HandshakeConfirmed,
                QuicConnectionEventKind.TimerExpired,
            ],
            observedKinds);
        Assert.Equal(3UL, runtime.TransitionSequence);
        Assert.Equal(clock.Ticks, runtime.LastTransitionTicks);
        Assert.True(runtime.HandshakeConfirmed);
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
