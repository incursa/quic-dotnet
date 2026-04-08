namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0013")]
public sealed class REQ_QUIC_CRT_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointRoutesLongHeaderDatagramsToTheMatchingRuntime()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, [0x10, 0x11]));
        Assert.True(endpoint.TryRegisterConnectionId(secondHandle, [0x30, 0x31]));

        TaskCompletionSource<QuicConnectionHandle> observedHandle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = endpoint.RunAsync(
            (handle, shardIndex, transition) =>
            {
                Assert.InRange(shardIndex, 0, endpoint.ShardCount - 1);
                if (transition.EventKind == QuicConnectionEventKind.PacketReceived)
                {
                    observedHandle.TrySetResult(handle);
                }
            },
            cancellationToken: cancellation.Token);

        byte[] datagram = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: [0x30, 0x31],
            sourceConnectionId: [0x20]);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            new QuicConnectionPathIdentity("203.0.113.3"));

        Assert.True(result.RoutedToConnection);
        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(secondHandle, result.Handle);
        Assert.Equal(secondHandle, await observedHandle.Task.WaitAsync(TimeSpan.FromSeconds(5)));

        cancellation.Cancel();
        await consumer;
        await endpoint.DisposeAsync();
        await firstRuntime.DisposeAsync();
        await secondRuntime.DisposeAsync();

        Assert.Equal(0UL, firstRuntime.TransitionSequence);
        Assert.Equal(1UL, secondRuntime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task EndpointRoutesShortHeaderDatagramsByTheLongestRegisteredPrefix()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, [0x10]));
        Assert.True(endpoint.TryRegisterConnectionId(secondHandle, [0x10, 0x11]));

        TaskCompletionSource<QuicConnectionHandle> observedHandle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource cancellation = new();

        Task consumer = endpoint.RunAsync(
            (handle, shardIndex, transition) =>
            {
                Assert.InRange(shardIndex, 0, endpoint.ShardCount - 1);
                if (transition.EventKind == QuicConnectionEventKind.PacketReceived)
                {
                    observedHandle.TrySetResult(handle);
                }
            },
            cancellationToken: cancellation.Token);

        byte[] datagram = QuicHeaderTestData.BuildShortHeader(0x00, [0x10, 0x11, 0x22, 0x33]);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            new QuicConnectionPathIdentity("203.0.113.4"));

        Assert.True(result.RoutedToConnection);
        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(secondHandle, result.Handle);
        Assert.Equal(secondHandle, await observedHandle.Task.WaitAsync(TimeSpan.FromSeconds(5)));

        cancellation.Cancel();
        await consumer;
        await endpoint.DisposeAsync();
        await firstRuntime.DisposeAsync();
        await secondRuntime.DisposeAsync();

        Assert.Equal(0UL, firstRuntime.TransitionSequence);
        Assert.Equal(1UL, secondRuntime.TransitionSequence);
    }
}
