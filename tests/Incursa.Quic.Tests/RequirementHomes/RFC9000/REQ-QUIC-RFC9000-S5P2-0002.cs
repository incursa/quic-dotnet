// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0002")]
public sealed class REQ_QUIC_RFC9000_S5P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointAssociatesPacketWithExistingConnectionRoute()
    {
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram(QuicS5P2PacketAssociationTestSupport.RouteConnectionId),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerCanCreateConnectionFromConformingInitialPacket()
    {
        byte[] clientInitialDestinationConnectionId =
        [
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        ];
        byte[] clientSourceConnectionId =
        [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        ];
        byte[] clientInitialPacket = InteropEndpointHostTestSupport.BuildProtectedInitialPacket(
            clientInitialDestinationConnectionId,
            clientSourceConnectionId);

        byte[] serverResponse = await QuicS5P2P2ServerPreAcceptanceTestSupport
            .SendConformingInitialAndReceiveServerInitialAsync(clientInitialPacket, clientSourceConnectionId);

        Assert.True(serverResponse.Length > 0);
    }
}
