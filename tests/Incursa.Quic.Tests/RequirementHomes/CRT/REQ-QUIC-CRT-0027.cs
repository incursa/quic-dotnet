namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0027")]
public sealed class REQ_QUIC_CRT_0027
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AcceptedStatelessResetTransitionsTheRuntimeToDraining()
    {
        FakeMonotonicClock clock = new(123_456_789);
        using QuicConnectionRuntimeEndpoint endpoint = new(2, clock);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.60");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 17UL, token));

        TaskCompletionSource<QuicConnectionTransitionResult> observedTransition = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = endpoint.RunAsync(
            (postedHandle, _, transition) =>
            {
                if (postedHandle == handle
                    && transition.EventKind == QuicConnectionEventKind.AcceptedStatelessReset)
                {
                    observedTransition.TrySetResult(transition);
                }
            },
            cancellationToken: cancellation.Token);

        QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(token),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, ingressResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, ingressResult.HandlingKind);
        Assert.Equal(handle, ingressResult.Handle);

        QuicConnectionTransitionResult transition = await observedTransition.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();
        await consumer;

        Assert.Equal(clock.Ticks, transition.ObservedAtTicks);
        Assert.Equal(QuicConnectionPhase.Draining, transition.CurrentPhase);
        Assert.True(transition.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.StatelessReset, runtime.TerminalState?.Origin);
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
