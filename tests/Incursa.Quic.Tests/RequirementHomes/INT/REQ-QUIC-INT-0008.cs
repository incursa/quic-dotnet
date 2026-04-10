using System.Net.Sockets;
using System.Collections.Concurrent;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0008")]
public sealed class REQ_QUIC_INT_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointHostShellBridgesTheLibraryRuntimeThroughAConnectedUdpSocketAndSurfacesOutboundHandshakeDatagrams()
    {
        var (serverSocket, clientSocket, serverEndPoint, clientEndPoint) = InteropEndpointHostTestSupport.CreateConnectedUdpSocketPair();
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = InteropEndpointHostTestSupport.CreateRuntime();

        try
        {
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            Assert.True(endpoint.TryRegisterConnection(handle, runtime));

            byte[] routeConnectionId = [0x10, 0x11];
            Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId));

            QuicTlsPacketProtectionMaterial material = InteropEndpointHostTestSupport.CreateHandshakeMaterial();
            QuicTransportParameters localTransportParameters = InteropEndpointHostTestSupport.CreateBootstrapLocalTransportParameters();
            QuicTransportParameters peerTransportParameters = InteropEndpointHostTestSupport.CreatePeerTransportParameters();

            Assert.True(endpoint.Host.TryPostEvent(handle, new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material))));

            ConcurrentQueue<QuicConnectionIngressResult> ingressResults = new();
            ConcurrentQueue<QuicConnectionTransitionResult> transitionResults = new();
            ConcurrentQueue<QuicConnectionEffect> effectResults = new();
            using ManualResetEventSlim ingressSeen = new(false);
            using ManualResetEventSlim packetReceivedSeen = new(false);
            using ManualResetEventSlim bootstrapSeen = new(false);
            using ManualResetEventSlim sendSeen = new(false);

            using InteropEndpointHost shell = new(
                endpoint,
                serverSocket,
                new QuicConnectionPathIdentity(
                    clientEndPoint.Address.ToString(),
                    serverEndPoint.Address.ToString(),
                    clientEndPoint.Port,
                    serverEndPoint.Port),
                ingressObserver: ingressResult =>
                {
                    ingressResults.Enqueue(ingressResult);
                    ingressSeen.Set();
                },
                transitionObserver: transitionResult =>
                {
                    transitionResults.Enqueue(transitionResult);
                    if (transitionResult.EventKind == QuicConnectionEventKind.PacketReceived)
                    {
                        packetReceivedSeen.Set();
                    }
                    else if (transitionResult.EventKind == QuicConnectionEventKind.HandshakeBootstrapRequested)
                    {
                        bootstrapSeen.Set();
                    }
                },
                effectObserver: effect =>
                {
                    effectResults.Enqueue(effect);
                    if (effect is QuicConnectionSendDatagramEffect)
                    {
                        sendSeen.Set();
                    }
            });

            _ = shell.RunAsync();

            Assert.True(endpoint.Host.TryPostEvent(handle, new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 3,
                LocalTransportParameters: localTransportParameters)));
            Assert.True(bootstrapSeen.Wait(TimeSpan.FromSeconds(5)));
            Assert.True(runtime.TlsState.HandshakeEgressCryptoBuffer.BufferedBytes > 0);

            byte[] peerTranscript = InteropEndpointHostTestSupport.CreateClientHandshakeTranscript(peerTransportParameters);
            byte[] protectedPeerPacket = InteropEndpointHostTestSupport.BuildProtectedHandshakePacket(
                material,
                peerTranscript,
                routeConnectionId);

            for (int i = 0; i < 16; i++)
            {
                int bytesSent = clientSocket.Send(protectedPeerPacket);
                Assert.Equal(protectedPeerPacket.Length, bytesSent);
            }

            Assert.True(ingressSeen.Wait(TimeSpan.FromSeconds(5)));
            Assert.All(ingressResults, result => Assert.True(result.RoutedToConnection));
            QuicConnectionIngressResult ingressResult = ingressResults.First();
            Assert.True(ingressResult.RoutedToConnection);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, ingressResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, ingressResult.HandlingKind);
            Assert.Equal(handle, ingressResult.Handle);

            Assert.True(packetReceivedSeen.Wait(TimeSpan.FromSeconds(5)));
            QuicConnectionTransitionResult packetReceivedResult = GetPacketReceivedTransitionResult(transitionResults);
            Assert.Equal(QuicConnectionEventKind.PacketReceived, packetReceivedResult.EventKind);
            Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);

            Assert.True(sendSeen.Wait(TimeSpan.FromSeconds(5)));
            Assert.True(runtime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeProtectMaterial));
            QuicConnectionSendDatagramEffect sendEffect = effectResults.OfType<QuicConnectionSendDatagramEffect>().Last();

            byte[] receivedDatagram = new byte[2048];
            clientSocket.ReceiveTimeout = 5000;
            int receivedBytes = clientSocket.Receive(receivedDatagram);
            Assert.Equal(sendEffect.Datagram.Length, receivedBytes);
            Assert.True(sendEffect.Datagram.Span.SequenceEqual(receivedDatagram.AsSpan(0, receivedBytes)));
            Assert.True(QuicPacketParser.TryClassifyHeaderForm(receivedDatagram.AsSpan(0, receivedBytes), out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Long, headerForm);
            Assert.True(QuicPacketParser.TryParseLongHeader(receivedDatagram.AsSpan(0, receivedBytes), out QuicLongHeaderPacket longHeader));
            Assert.Equal(QuicLongPacketTypeBits.Handshake, longHeader.LongPacketTypeBits);

            QuicHandshakeFlowCoordinator coordinator = new();
            Assert.True(coordinator.TryOpenHandshakePacket(
                receivedDatagram.AsSpan(0, receivedBytes),
                handshakeProtectMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            Assert.True(QuicFrameCodec.TryParseCryptoFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out QuicCryptoFrame outboundCryptoFrame,
                out int bytesConsumed));
            Assert.True(bytesConsumed > 0);
            Assert.Equal(0UL, outboundCryptoFrame.Offset);
            Assert.True(
                InteropEndpointHostTestSupport.CreateExpectedEncryptedExtensionsTranscript()
                    .AsSpan()
                    .SequenceEqual(outboundCryptoFrame.CryptoData));
        }
        finally
        {
            serverSocket.Dispose();
            clientSocket.Dispose();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteMissesRemainUnroutableAndDoNotReachTheRuntimeConsumer()
    {
        var (serverSocket, clientSocket, serverEndPoint, clientEndPoint) = InteropEndpointHostTestSupport.CreateConnectedUdpSocketPair();
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = InteropEndpointHostTestSupport.CreateRuntime();

        try
        {
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            Assert.True(endpoint.TryRegisterConnection(handle, runtime));

            ConcurrentQueue<QuicConnectionIngressResult> ingressResults = new();
            ConcurrentQueue<QuicConnectionTransitionResult> transitionResults = new();
            ConcurrentQueue<QuicConnectionEffect> effectResults = new();
            using ManualResetEventSlim ingressSeen = new(false);

            using InteropEndpointHost shell = new(
                endpoint,
                serverSocket,
                new QuicConnectionPathIdentity(
                    clientEndPoint.Address.ToString(),
                    serverEndPoint.Address.ToString(),
                    clientEndPoint.Port,
                    serverEndPoint.Port),
                ingressObserver: ingressResult =>
                {
                    ingressResults.Enqueue(ingressResult);
                    ingressSeen.Set();
                },
                transitionObserver: transitionResult => transitionResults.Enqueue(transitionResult),
                effectObserver: effect => effectResults.Enqueue(effect));

            _ = shell.RunAsync();

            QuicTlsPacketProtectionMaterial material = InteropEndpointHostTestSupport.CreateHandshakeMaterial();
            byte[] peerTranscript = InteropEndpointHostTestSupport.CreateClientHandshakeTranscript(
                InteropEndpointHostTestSupport.CreatePeerTransportParameters());
            byte[] protectedPeerPacket = InteropEndpointHostTestSupport.BuildProtectedHandshakePacket(
                material,
                peerTranscript,
                [0x30, 0x31]);

            int bytesSent = clientSocket.Send(protectedPeerPacket);
            Assert.Equal(protectedPeerPacket.Length, bytesSent);

            Assert.True(ingressSeen.Wait(TimeSpan.FromSeconds(5)));
            QuicConnectionIngressResult ingressResult = Assert.Single(ingressResults);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, ingressResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.None, ingressResult.HandlingKind);
            Assert.Null(ingressResult.Handle);
            Assert.Empty(transitionResults);
            Assert.Empty(effectResults);
        }
        finally
        {
            serverSocket.Dispose();
            clientSocket.Dispose();
        }
    }

    private static QuicConnectionTransitionResult GetPacketReceivedTransitionResult(ConcurrentQueue<QuicConnectionTransitionResult> transitionResults)
    {
        foreach (QuicConnectionTransitionResult result in transitionResults)
        {
            if (result.EventKind == QuicConnectionEventKind.PacketReceived)
            {
                return result;
            }
        }

        throw new InvalidOperationException("PacketReceived transition was not observed.");
    }
}
