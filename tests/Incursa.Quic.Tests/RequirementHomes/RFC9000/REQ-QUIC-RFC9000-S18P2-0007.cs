// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0007")]
public sealed class REQ_QUIC_RFC9000_S18P2_0007
{
    private const ulong LocalMaxUdpPayloadSize = 1200;
    private static readonly byte[] RouteConnectionId = [0x51, 0x52, 0x53, 0x54];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReceiveDatagram_RoutesDatagramAtTheLocalMaximumUdpPayloadSize()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.70");
        byte[] datagram = BuildShortHeaderDatagram((int)LocalMaxUdpPayloadSize);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, RouteConnectionId));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionUpdateMaxUdpPayloadSizeEffect(LocalMaxUdpPayloadSize)));

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
    public async Task ReceiveDatagram_DropsDatagramLargerThanTheLocalMaximumUdpPayloadSize()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.71");
        byte[] datagram = BuildShortHeaderDatagram((int)LocalMaxUdpPayloadSize + 1);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, RouteConnectionId));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionUpdateMaxUdpPayloadSizeEffect(LocalMaxUdpPayloadSize)));

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

        Assert.Equal(QuicConnectionIngressDisposition.Dropped, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Equal(handle, result.Handle);
        Assert.False(observedHandle.Task.IsCompleted);

        cancellation.Cancel();
        await consumer;
        await endpoint.DisposeAsync();
        await runtime.DisposeAsync();

        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ReceiveDatagram_UsesDefaultMaximumUdpPayloadSizeWhenNoLocalParameterWasPublished()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.72");

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, RouteConnectionId));

        QuicConnectionIngressResult exactLimitResult = endpoint.ReceiveDatagram(
            BuildShortHeaderDatagram((int)QuicTransportParameters.DefaultMaxUdpPayloadSize),
            pathIdentity);
        QuicConnectionIngressResult overLimitResult = endpoint.ReceiveDatagram(
            BuildShortHeaderDatagram((int)QuicTransportParameters.DefaultMaxUdpPayloadSize + 1),
            pathIdentity);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, exactLimitResult.Disposition);
        Assert.Equal(handle, exactLimitResult.Handle);
        Assert.Equal(QuicConnectionIngressDisposition.Dropped, overLimitResult.Disposition);
        Assert.Equal(handle, overLimitResult.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void LocalTransportParameterCommitPublishesMaximumUdpPayloadSizeEndpointEffect()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicTransportParameters localTransportParameters = new()
        {
            MaxUdpPayloadSize = 1350,
        };

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.LocalTransportParametersReady,
                    TransportParameters: localTransportParameters)),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Contains(
            result.Effects,
            effect => effect is QuicConnectionUpdateMaxUdpPayloadSizeEffect { MaxUdpPayloadSize: 1350UL });
    }

    private static byte[] BuildShortHeaderDatagram(int datagramLength)
    {
        Assert.True(datagramLength > RouteConnectionId.Length + 1);

        byte[] remainder = new byte[datagramLength - 1];
        RouteConnectionId.CopyTo(remainder.AsSpan());
        byte[] datagram = QuicHeaderTestData.BuildShortHeader(0x00, remainder);

        Assert.Equal(datagramLength, datagram.Length);
        return datagram;
    }
}
