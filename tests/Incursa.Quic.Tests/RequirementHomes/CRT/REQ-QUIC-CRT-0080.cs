namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0080")]
public sealed class REQ_QUIC_CRT_0080
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointDispatchesEligibleStatelessResetDatagramsIntoTheRuntime()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.30");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 61UL, token));

        TaskCompletionSource<QuicConnectionHandle> observedHandle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = endpoint.RunAsync(
            (postedHandle, _, transition) =>
            {
                if (transition.EventKind == QuicConnectionEventKind.AcceptedStatelessReset)
                {
                    observedHandle.TrySetResult(postedHandle);
                }
            },
            cancellationToken: cancellation.Token);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            pathIdentity);

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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointLeavesIneligibleStatelessResetDatagramsUnrouted()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.31");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 62UL, token));

        byte[] datagram = QuicHeaderTestData.BuildShortHeader(0x00, [0x55, 0x56, 0x57]);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
