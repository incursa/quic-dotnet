namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0015")]
public sealed class REQ_QUIC_CRT_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointMatchesStatelessResetOnlyForTheOwningRemoteAddress()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, new QuicConnectionPathIdentity("203.0.113.10")));

        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 41UL, token));

        TaskCompletionSource<QuicConnectionHandle> observedHandle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = endpoint.RunAsync(
            (postedHandle, _, transition) =>
            {
                if (transition.EventKind == QuicConnectionEventKind.StatelessResetMatched)
                {
                    observedHandle.TrySetResult(postedHandle);
                }
            },
            cancellationToken: cancellation.Token);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            new QuicConnectionPathIdentity("203.0.113.10"));

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
        Assert.Equal(handle, await observedHandle.Task.WaitAsync(TimeSpan.FromSeconds(5)));

        cancellation.Cancel();
        await consumer;
        await endpoint.DisposeAsync();
        await runtime.DisposeAsync();

        Assert.Equal(1UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointRejectsStatelessResetDatagramsFromDifferentRemoteAddresses()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, new QuicConnectionPathIdentity("203.0.113.11")));

        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 42UL, token));

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            new QuicConnectionPathIdentity("203.0.113.99"));

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
