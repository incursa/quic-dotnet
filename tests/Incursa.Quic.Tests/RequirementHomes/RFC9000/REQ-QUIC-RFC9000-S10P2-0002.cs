// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2-0002">Endpoints that have some alternative means to ensure that late-arriving packets do not induce a response, such as those that are able to close the UDP socket, MAY end these states earlier to allow for faster resource recovery.</workbench-requirement>
/// </workbench-requirements>
[Collection(QuicLoopbackNetworkTestCollection.Name)]
[Requirement("REQ-QUIC-RFC9000-S10P2-0002")]
public sealed class REQ_QUIC_RFC9000_S10P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S10P2-0002")]
    public async Task EndpointHostDisposalPreventsClosingStatePacketsFromInducingAResponse()
    {
        (Socket serverSocket, Socket clientSocket, IPEndPoint serverEndPoint, IPEndPoint clientEndPoint) =
            InteropEndpointHostTestSupport.CreateConnectedUdpSocketPair();

        using Socket disposedServerSocket = serverSocket;
        using Socket disposedClientSocket = clientSocket;
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = CreatePathIdentity(clientEndPoint, serverEndPoint);
        byte[] routeConnectionId = [0x66, 0x02, 0xA0, 0x02];

        ConfigureClosingEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId);

        await using QuicConnectionEndpointHost host = new(endpoint, disposedServerSocket, pathIdentity);
        _ = host.RunAsync();
        await Task.Yield();
        await host.DisposeAsync();

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            routeConnectionId,
            triggeringPacketLength: 80);

        Assert.Equal(triggeringPacket.Length, disposedClientSocket.Send(triggeringPacket));
        await AssertNoDatagramReceivedAsync(disposedClientSocket, TimeSpan.FromSeconds(1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S10P2-0002")]
    public async Task EndpointHostStillRespondsToClosingStatePacketsWhileTheSocketRemainsOpen()
    {
        (Socket serverSocket, Socket clientSocket, IPEndPoint serverEndPoint, IPEndPoint clientEndPoint) =
            InteropEndpointHostTestSupport.CreateConnectedUdpSocketPair();

        using Socket disposedServerSocket = serverSocket;
        using Socket disposedClientSocket = clientSocket;
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity pathIdentity = CreatePathIdentity(clientEndPoint, serverEndPoint);
        byte[] routeConnectionId = [0x66, 0x02, 0xA0, 0x03];

        ConfigureClosingEndpoint(endpoint, runtime, handle, pathIdentity, routeConnectionId);

        await using QuicConnectionEndpointHost host = new(endpoint, disposedServerSocket, pathIdentity);
        _ = host.RunAsync();
        await Task.Yield();

        byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
            routeConnectionId,
            triggeringPacketLength: 80);

        Assert.Equal(triggeringPacket.Length, disposedClientSocket.Send(triggeringPacket));

        byte[] response = new byte[4096];
        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await disposedClientSocket.ReceiveAsync(response.AsMemory(), SocketFlags.None, receiveTimeout.Token);

        Assert.True(bytesReceived > 0);
    }

    private static void ConfigureClosingEndpoint(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity,
        byte[] routeConnectionId)
    {
        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: 202UL));

        QuicConnectionTransitionResult transition = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                new QuicConnectionCloseMetadata(
                    QuicTransportErrorCode.NoError,
                    ApplicationErrorCode: null,
                    TriggeringFrameType: 0x1c,
                    ReasonPhrase: "closing")),
            nowTicks: 1);

        Assert.True(transition.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
    }

    private static QuicConnectionPathIdentity CreatePathIdentity(IPEndPoint clientEndPoint, IPEndPoint serverEndPoint)
    {
        return new(
            clientEndPoint.Address.ToString(),
            serverEndPoint.Address.ToString(),
            clientEndPoint.Port,
            serverEndPoint.Port);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 100);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 200,
                PeerMaxIdleTimeoutMicros: 200,
                CurrentProbeTimeoutMicros: 100),
            nowTicks: 0);

        return runtime;
    }

    private static async Task AssertNoDatagramReceivedAsync(Socket socket, TimeSpan timeout)
    {
        byte[] response = new byte[4096];
        using CancellationTokenSource receiveTimeout = new(timeout);

        try
        {
            int bytesReceived = await socket.ReceiveAsync(response.AsMemory(), SocketFlags.None, receiveTimeout.Token);
            Assert.Fail($"Expected the closed endpoint host to suppress late responses, but received {bytesReceived} byte(s).");
        }
        catch (OperationCanceledException) when (receiveTimeout.IsCancellationRequested)
        {
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.ConnectionRefused)
        {
        }
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
