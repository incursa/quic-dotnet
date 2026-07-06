// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P1-0003")]
public sealed class REQ_QUIC_RFC9000_S5P2P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointProcessesShortHeaderPacketWithMatchingClientSelectedDestinationConnectionId()
    {
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(
                QuicS5P2PacketAssociationTestSupport.RouteConnectionId),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotProcessShortHeaderPacketWithDifferentClientSelectedDestinationConnectionId()
    {
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram([0x40, 0x41]),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointProcessesShortHeaderPacketWithMaximumLengthClientSelectedDestinationConnectionId()
    {
        byte[] maximumLengthConnectionId = QuicS5P2PacketAssociationTestSupport.BuildMaximumLengthConnectionId();
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(maximumLengthConnectionId);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(maximumLengthConnectionId),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void EndpointFuzzRoutesOnlyShortHeaderPacketsWithRegisteredClientSelectedDestinationConnectionIds()
    {
        byte[][] routeIds =
        [
            [0x30],
            [0x30, 0x31],
            [0x30, 0x31, 0x32, 0x33],
            QuicS5P2PacketAssociationTestSupport.BuildMaximumLengthConnectionId(),
        ];

        foreach (byte[] routeId in routeIds)
        {
            var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(routeId);
            using QuicConnectionRuntime runtime = scenario.Runtime;
            using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

            QuicConnectionIngressResult matched = endpoint.ReceiveDatagram(
                QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(routeId),
                QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());
            byte[] mismatchedRouteId = routeId.ToArray();
            mismatchedRouteId[^1] ^= 0x7F;
            QuicConnectionIngressResult unmatched = endpoint.ReceiveDatagram(
                QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(mismatchedRouteId),
                QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matched.Disposition);
            Assert.Equal(scenario.Handle, matched.Handle);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unmatched.Disposition);
            Assert.Null(unmatched.Handle);
        }
    }
}
