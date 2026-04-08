namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0018")]
public sealed class REQ_QUIC_CRT_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task MultipleProducersCanEnqueueWithoutMutatingConnectionStateInline()
    {
        FakeMonotonicClock clock = new(987_654_321);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        const int producerCount = 32;

        Task<bool>[] producerTasks = Enumerable.Range(0, producerCount)
            .Select(index => Task.Run(() => runtime.TryPostLocalApiEvent(
                new QuicConnectionTransportParametersCommittedEvent(
                    ObservedAtTicks: index,
                    TransportFlags: QuicConnectionTransportState.DisableActiveMigration))))
            .ToArray();

        bool[] posted = await Task.WhenAll(producerTasks);

        Assert.All(posted, value => Assert.True(value));
        Assert.Equal(0UL, runtime.TransitionSequence);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionTransportState.None, runtime.TransportFlags);

        List<ulong> observedSequences = [];
        TaskCompletionSource<bool> observedAllEvents = new(TaskCreationOptions.RunContinuationsAsynchronously);

        Task consumer = runtime.RunAsync(
            transition =>
            {
                observedSequences.Add(transition.Sequence);

                if (observedSequences.Count == producerCount)
                {
                    observedAllEvents.TrySetResult(true);
                }
            });

        await observedAllEvents.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await runtime.DisposeAsync();
        await consumer;

        Assert.Equal(Enumerable.Range(1, producerCount).Select(value => (ulong)value), observedSequences);
        Assert.Equal((ulong)producerCount, runtime.TransitionSequence);
        Assert.Equal(QuicConnectionTransportState.DisableActiveMigration, runtime.TransportFlags);
        Assert.False(runtime.TryPostNetworkEvent(new QuicConnectionPacketReceivedEvent(
            ObservedAtTicks: 99,
            new QuicConnectionPathIdentity("203.0.113.2"),
            ReadOnlyMemory<byte>.Empty)));
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
