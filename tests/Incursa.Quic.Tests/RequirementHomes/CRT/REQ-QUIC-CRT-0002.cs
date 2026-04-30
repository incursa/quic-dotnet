namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0002")]
public sealed class REQ_QUIC_CRT_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointHandlesVersionNegotiationBeforeRoutingOrDispatch()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x10, 0x11]));

        byte[] datagram = QuicHeaderTestData.BuildVersionNegotiation(
            0x00,
            [0x10, 0x11],
            [0x20],
            1u);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            new QuicConnectionPathIdentity("203.0.113.120"));

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.VersionNegotiation, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task EndpointRoutesKnownShortHeaderTrafficBeforeResetScreening()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.121");
        byte[] routeId = [0x10, 0x11];
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x70);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 171UL, token));

        TaskCompletionSource<QuicConnectionHandle> observedHandle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = endpoint.RunAsync(
            (postedHandle, _, transition) =>
            {
                if (transition.EventKind == QuicConnectionEventKind.PacketReceived)
                {
                    observedHandle.TrySetResult(postedHandle);
                }
            },
            cancellationToken: cancellation.Token);

        byte[] datagram = new byte[1 + routeId.Length + 8 + token.Length];
        datagram[0] = 0x40;
        routeId.CopyTo(datagram.AsSpan(1));
        token.CopyTo(datagram.AsSpan(datagram.Length - token.Length));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
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
    public void EndpointScreensRouteMissesForStatelessResetBeforeUnroutableDisposition()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.122");
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x71);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, 172UL, token));

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);
        datagram[0] = 0x40;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }
}
