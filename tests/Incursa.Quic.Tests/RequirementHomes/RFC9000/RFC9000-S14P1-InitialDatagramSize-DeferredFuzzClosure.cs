// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S14P1_InitialDatagramSize_DeferredFuzzClosure
{
    private const int InitialRouteDatagramOverhead = 20;

    private static readonly byte[] DestinationConnectionId = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    private static readonly byte[] SourceConnectionId = [0x20];

    [Fact]
    [Requirement("RFC9000-S14-1-P3-S1-R01")]
    [Requirement("RFC9000-S14-1-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void InitialDatagramSizeFuzz_DiscardsOnlyInitialDatagramsBelowTheMinimum()
    {
        int minimum = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;
        int[] payloadLengths = [minimum - 64, minimum - 32, minimum - 1, minimum, minimum + 1, minimum + 128];

        foreach (int payloadLength in payloadLengths)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new($"203.0.113.{payloadLength % 200}");
            byte[] initialDatagram = BuildInitialDatagram(payloadLength);
            byte[] handshakeDatagram = BuildHandshakeDatagram(payloadLength);

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryRegisterConnectionId(handle, DestinationConnectionId));

            QuicConnectionIngressResult initialResult = endpoint.ReceiveDatagram(initialDatagram, pathIdentity);
            QuicConnectionIngressResult handshakeResult = endpoint.ReceiveDatagram(handshakeDatagram, pathIdentity);

            if (payloadLength < minimum)
            {
                Assert.Equal(QuicConnectionIngressDisposition.Malformed, initialResult.Disposition);
                Assert.Equal(QuicConnectionEndpointHandlingKind.None, initialResult.HandlingKind);
                Assert.Null(initialResult.Handle);
            }
            else
            {
                Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, initialResult.Disposition);
                Assert.Equal(QuicConnectionEndpointHandlingKind.None, initialResult.HandlingKind);
                Assert.Equal(handle, initialResult.Handle);
            }

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, handshakeResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, handshakeResult.HandlingKind);
            Assert.Equal(handle, handshakeResult.Handle);
        }
    }

    [Theory]
    [InlineData(1136)]
    [InlineData(1168)]
    [InlineData(1199)]
    [Requirement("RFC9000-S14-1-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task ListenerHostUndersizedInitialFuzz_CanCloseWithProtocolViolation(int payloadLength)
    {
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) =>
            {
                callbackEntered.TrySetResult(true);
                return ValueTask.FromResult(new QuicServerConnectionOptions());
            },
            listenBacklog: 1);

        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        clientSocket.Connect(listenEndPoint);

        _ = listenerHost.RunAsync();
        await Task.Yield();

        byte[] datagram = BuildInitialDatagram(payloadLength);
        Assert.Equal(datagram.Length, clientSocket.Send(datagram));

        byte[] responseBuffer = new byte[64];
        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(responseBuffer.AsMemory(), SocketFlags.None, receiveTimeout.Token);

        byte[] expectedClose = QuicFrameTestData.BuildConnectionCloseFrame(
            new QuicConnectionCloseFrame(
                QuicTransportErrorCode.ProtocolViolation,
                triggeringFrameType: 0,
                []));

        Assert.Equal(expectedClose.Length, bytesReceived);
        Assert.True(expectedClose.AsSpan().SequenceEqual(responseBuffer.AsSpan(0, bytesReceived)));
        Assert.False(callbackEntered.Task.IsCompleted);
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
