namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0008")]
public sealed class REQ_QUIC_CRT_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DedicatedAndShardedOwnersApplyTheSameConnectionTransition()
    {
        QuicConnectionPeerHandshakeTranscriptCompletedEvent connectionEvent = new(ObservedAtTicks: 123);
        using QuicConnectionRuntime dedicatedRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionTransitionResult dedicatedResult = dedicatedRuntime.Transition(connectionEvent, nowTicks: 123);

        using QuicConnectionRuntimeHost host = new(1, new FakeMonotonicClock(123));
        using QuicConnectionRuntime shardedRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = host.AllocateConnectionHandle();
        TaskCompletionSource<QuicConnectionTransitionResult> observedResult = new(TaskCreationOptions.RunContinuationsAsynchronously);

        Assert.True(host.TryRegisterConnection(handle, shardedRuntime));
        Task consumer = host.RunAsync((observedHandle, _, result) =>
        {
            if (observedHandle == handle)
            {
                observedResult.TrySetResult(result);
            }
        });

        Assert.True(host.TryPostEvent(handle, connectionEvent));
        QuicConnectionTransitionResult shardedResult = await observedResult.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await host.DisposeAsync();
        await consumer;
        await shardedRuntime.DisposeAsync();

        Assert.Equal(dedicatedResult.EventKind, shardedResult.EventKind);
        Assert.Equal(dedicatedResult.PreviousPhase, shardedResult.PreviousPhase);
        Assert.Equal(dedicatedResult.CurrentPhase, shardedResult.CurrentPhase);
        Assert.Equal(dedicatedResult.StateChanged, shardedResult.StateChanged);
        Assert.True(dedicatedRuntime.PeerHandshakeTranscriptCompleted);
        Assert.True(shardedRuntime.PeerHandshakeTranscriptCompleted);
    }
}
