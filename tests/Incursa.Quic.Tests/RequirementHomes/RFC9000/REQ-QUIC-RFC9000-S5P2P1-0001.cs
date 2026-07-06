// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P1-0001")]
public sealed class REQ_QUIC_RFC9000_S5P2P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointProcessesLongHeaderPacketWithMatchingClientSelectedDestinationConnectionId()
    {
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram(
                QuicS5P2PacketAssociationTestSupport.RouteConnectionId),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P1-0001")]
    public void Fuzz_EndpointRoutesLongHeaderPacketsByMatchingClientSelectedDestinationConnectionId()
    {
        byte[][] routeConnectionIds =
        [
            [0x01],
            [0x30, 0x31],
            [0x44, 0x45, 0x46, 0x47],
            QuicS5P2PacketAssociationTestSupport.BuildMaximumLengthConnectionId(),
        ];

        foreach (byte[] routeConnectionId in routeConnectionIds)
        {
            var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(routeConnectionId);
            using QuicConnectionRuntime runtime = scenario.Runtime;
            using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

            QuicConnectionIngressResult matched = endpoint.ReceiveDatagram(
                QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram(routeConnectionId),
                QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matched.Disposition);
            Assert.Equal(scenario.Handle, matched.Handle);
        }
    }
}
