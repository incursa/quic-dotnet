// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S5P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S5P2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void NonZeroConnectionIdAssociationFuzz_RoutesOnlyPacketsWithRegisteredDestinationConnectionIds()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            byte[] registeredConnectionId = CreateConnectionId((byte)(0x30 + iteration), 1 + (iteration % QuicConnectionIdKey.MaximumLength));
            byte[] unregisteredConnectionId = CreateConnectionId((byte)(0x80 + iteration), registeredConnectionId.Length);
            var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(registeredConnectionId);
            using QuicConnectionRuntime runtime = scenario.Runtime;
            using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;
            QuicConnectionPathIdentity pathIdentity = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: $"203.0.113.{10 + iteration}",
                remotePort: 44330 + iteration);

            QuicConnectionIngressResult matchedHandshake = endpoint.ReceiveDatagram(
                QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram(registeredConnectionId),
                pathIdentity);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matchedHandshake.Disposition);
            Assert.Equal(scenario.Handle, matchedHandshake.Handle);

            QuicConnectionIngressResult matchedShortHeader = endpoint.ReceiveDatagram(
                QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(registeredConnectionId),
                pathIdentity);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matchedShortHeader.Disposition);
            Assert.Equal(scenario.Handle, matchedShortHeader.Handle);

            QuicConnectionIngressResult unmatched = endpoint.ReceiveDatagram(
                QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram(unregisteredConnectionId),
                pathIdentity);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unmatched.Disposition);
            Assert.Null(unmatched.Handle);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P2-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroLengthConnectionIdAssociationFuzz_AllowsDestinationEndpointMatchingOnly()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: $"203.0.113.{40 + iteration}",
                localAddress: "192.0.2.10",
                remotePort: 44330 + iteration,
                localPort: 4433);
            QuicConnectionPathIdentity changedRemoteEndpoint = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: $"203.0.113.{80 + iteration}",
                localAddress: "192.0.2.10",
                remotePort: 45330 + iteration,
                localPort: 4433);
            QuicConnectionPathIdentity changedLocalEndpoint = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: $"203.0.113.{40 + iteration}",
                localAddress: "192.0.2.11",
                remotePort: 44330 + iteration,
                localPort: 4434);
            var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
                ReadOnlySpan<byte>.Empty,
                registeredPath);
            using QuicConnectionRuntime runtime = scenario.Runtime;
            using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;
            byte[] datagram = QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram([]);

            QuicConnectionIngressResult remoteChanged = endpoint.ReceiveDatagram(datagram, changedRemoteEndpoint);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, remoteChanged.Disposition);
            Assert.Equal(scenario.Handle, remoteChanged.Handle);

            QuicConnectionIngressResult localChanged = endpoint.ReceiveDatagram(datagram, changedLocalEndpoint);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, localChanged.Disposition);
            Assert.Null(localChanged.Handle);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P2-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PacketProtectionFailureFuzz_DiscardsPacketsWithoutProcessingProtectedContents()
    {
        for (int iteration = 0; iteration < 12; iteration++)
        {
            byte[] initialDestinationConnectionId = CreateConnectionId((byte)(0xA0 + iteration), 4 + (iteration % 5));
            using QuicConnectionRuntime runtime =
                QuicS5P2PacketAssociationTestSupport.CreateServerRuntimeWithInitialProtection(initialDestinationConnectionId);
            byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
                new QuicCryptoFrame(
                    offset: 0,
                    cryptoData: [(byte)(0x40 + iteration), (byte)(0x50 + iteration), (byte)(0x60 + iteration)]));
            byte[] protectedPacket = QuicS5P2PacketAssociationTestSupport.BuildProtectedClientInitialPacket(
                initialDestinationConnectionId,
                cryptoPayload);
            byte[] tamperedPacket = QuicS5P2PacketAssociationTestSupport.TamperLastByte(protectedPacket);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: iteration,
                    new QuicConnectionPathIdentity($"203.0.113.{120 + iteration}", RemotePort: 443),
                    tamperedPacket),
                nowTicks: iteration);

            Assert.Null(runtime.TerminalState);
            Assert.False(runtime.PeerHandshakeTranscriptCompleted);
            Assert.Equal(0, runtime.TlsState.InitialIngressCryptoBuffer.BufferedBytes);
            Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        }
    }

    private static byte[] CreateConnectionId(byte startValue, int length)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = unchecked((byte)(startValue + index));
        }

        return connectionId;
    }
}
