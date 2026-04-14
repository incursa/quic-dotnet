namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0019">If a peer receives a Stateless Reset, it MUST immediately end the connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0019")]
public sealed class REQ_QUIC_RFC9000_S10P3_0019
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AcceptedStatelessResetTransitionsTheRuntimeToDraining()
    {
        FakeMonotonicClock clock = new(123_456_791);
        using QuicConnectionRuntimeEndpoint endpoint = new(2, clock);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.90");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x90);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 191UL, token));

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

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(datagram, pathIdentity);

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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReceiveDatagram_KeepsTheRuntimeAliveWhenTheResetTokenDoesNotMatch()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.91");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x91);
        byte[] nonMatchingToken = QuicStatelessResetRequirementTestData.CreateToken(0xA1);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 192UL, token));

        QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(
            QuicStatelessResetRequirementTestData.FormatDatagram(nonMatchingToken),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, ingressResult.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, ingressResult.HandlingKind);
        Assert.Null(ingressResult.Handle);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(0UL, runtime.TransitionSequence);
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
