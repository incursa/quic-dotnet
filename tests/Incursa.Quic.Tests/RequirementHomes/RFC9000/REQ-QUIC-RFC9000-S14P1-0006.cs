namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P1-0006">A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller than the smallest allowed maximum datagram size of 1200 bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P1-0006")]
public sealed class REQ_QUIC_RFC9000_S14P1_0006
{
    private const int InitialRouteDatagramOverhead = 20;

    private static readonly byte[] DestinationConnectionId = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    private static readonly byte[] SourceConnectionId = [0x20];

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ReceiveDatagram_DiscardsUndersizedInitialDatagramsEvenWhenTheyMatchARegisteredRoute()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.6");
        byte[] datagram = BuildInitialDatagram(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, DestinationConnectionId));

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

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.Malformed, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
        Assert.False(observedHandle.Task.IsCompleted);

        cancellation.Cancel();
        await consumer;
        await endpoint.DisposeAsync();
        await runtime.DisposeAsync();

        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReceiveDatagram_RoutesSubMinimumHandshakeDatagrams()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.7");
        byte[] datagram = BuildHandshakeDatagram(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, DestinationConnectionId));

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

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.True(result.RoutedToConnection);
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
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task ReceiveDatagram_AllowsInitialDatagramsAtTheMinimumSize()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.8");
        byte[] datagram = BuildInitialDatagram(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, DestinationConnectionId));

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

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(datagram, pathIdentity);

        Assert.True(result.RoutedToConnection);
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

    private static byte[] BuildInitialDatagram(int datagramPayloadLength)
    {
        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: QuicVersionNegotiation.Version1,
            destinationConnectionId: DestinationConnectionId,
            sourceConnectionId: SourceConnectionId,
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: new byte[datagramPayloadLength - InitialRouteDatagramOverhead]));
    }

    private static byte[] BuildHandshakeDatagram(int datagramPayloadLength)
    {
        return QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: DestinationConnectionId,
            sourceConnectionId: SourceConnectionId,
            protectedPayload: new byte[datagramPayloadLength - InitialRouteDatagramOverhead]);
    }
}
