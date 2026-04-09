namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0020")]
public sealed class REQ_QUIC_CRT_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ASingleConnectionStaysOnTheSameShardAcrossConcurrentPosts()
    {
        QuicConnectionRuntimeHost host = new(4);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = host.AllocateConnectionHandle();

        Assert.True(host.TryRegisterConnection(handle, runtime));

        List<int> observedShardIndexes = [];
        TaskCompletionSource<bool> observedAllTransitions = new(TaskCreationOptions.RunContinuationsAsynchronously);

        Task consumer = host.RunAsync(
            (observedHandle, shardIndex, _) =>
            {
                if (observedHandle != handle)
                {
                    return;
                }

                observedShardIndexes.Add(shardIndex);
                if (observedShardIndexes.Count == 32)
                {
                    observedAllTransitions.TrySetResult(true);
                }
            });

        Task<bool>[] producerTasks = Enumerable.Range(0, 32)
            .Select(_ => Task.Run(() => host.TryPostEvent(
                handle,
                new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 0))))
            .ToArray();

        bool[] posted = await Task.WhenAll(producerTasks);
        Assert.All(posted, value => Assert.True(value));

        await observedAllTransitions.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await host.DisposeAsync();
        await consumer;
        await runtime.DisposeAsync();

        Assert.Equal(32, observedShardIndexes.Count);
        Assert.All(observedShardIndexes, shardIndex => Assert.Equal(observedShardIndexes[0], shardIndex));
        Assert.Equal(32UL, runtime.TransitionSequence);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
    }
}
